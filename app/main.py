from fastapi import FastAPI, HTTPException, Query, Depends, Request
from fastapi.responses import StreamingResponse, JSONResponse
from database import (
    stream_table_jsonl, 
    TABLE_REGISTRY, 
    init_db_engine, 
    get_db_engine,
    dump_table_to_gcs
)
from pydantic import BaseModel, Field
import logging  
from security import get_current_user, get_user_id_from_token
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Initialize the API App
app = FastAPI(
    title="Query Execution Engine",
    description="Production-grade data export API for Wiley big data systems",
    version="2.0.0"
)
logger = logging.getLogger("uvicorn")

# CORS Configuration
origins = [
    "http://localhost:3000",
    "http://localhost:8000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiter
def get_user_identifier(request: Request) -> str:
    """Extract user ID from JWT for rate limiting."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        user_id = get_user_id_from_token(token)
        if user_id != "invalid_user":
            return f"user:{user_id}"
    
    client_ip = request.client.host if request.client else "unknown_ip"
    return f"ip:{client_ip}"

limiter = Limiter(key_func=get_user_identifier)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Lifecycle Events
@app.on_event("startup")
async def startup_event():
    """Initialize resources before serving requests."""
    init_db_engine()
    logger.info("✅ Application startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    """Release resources during shutdown."""
    engine = get_db_engine()
    if engine:
        engine.dispose()
    logger.info("🛑 Clean shutdown complete")    


# Health Check Endpoint
@app.get("/")
@limiter.limit("100/minute") 
async def health_check(request: Request):
    """Liveness probe endpoint for Cloud Run health checks."""
    return {
        "status": "healthy", 
        "service": "query-engine",
        "version": "2.0.0",
        "features": ["streaming_export", "gcs_export", "jwt_auth", "rate_limiting"]
    }


# Request model for GCS exports
class GCSExportRequest(BaseModel):
    """Request model for GCS export."""
    bucket_name: str = Field(..., description="GCS bucket name (e.g., 'wiley-data-exports')")
    page: int = Field(default=1, gt=0, description="Page number (1-indexed)")
    total_pages: int = Field(default=10, gt=0, le=500, description="Total pages (max 500)")
    folder_prefix: str = Field(default="exports", description="Folder prefix in bucket")


# Streaming Export Endpoint
@app.get("/export/{table_key}")
@limiter.limit("100/minute")
async def export_table(
    request: Request,
    table_key: str,
    page: int = Query(1, gt=0, description="Page number (1-indexed)"), 
    total_pages: int = Query(10, ge=1, le=500, description="Total pages (max 500)"), 
    current_user: dict = Depends(get_current_user)
):
    """
    Export table data in JSONL format with streaming.
    Returns data directly in HTTP response.
    """
    if table_key not in TABLE_REGISTRY:
        logger.warning(f"Invalid table requested: {table_key}")
        raise HTTPException(
            status_code=404, 
            detail=f"Table '{table_key}' not found. Available: {list(TABLE_REGISTRY.keys())}"
        )

    user_id = current_user.get("sub", "unknown")
    logger.info(
        f"Streaming export by user={user_id} | "
        f"table={table_key} | page={page}/{total_pages}"
    )
    
    try:
        data_generator = stream_table_jsonl(
            table_key=table_key,
            page_number=page,
            total_pages=total_pages
        )
        
        return StreamingResponse(
            data_generator, 
            media_type="application/x-ndjson",
            headers={
                "Content-Disposition": f"attachment; filename={table_key}_page{page}_of_{total_pages}.jsonl",
                "X-Page-Number": str(page),
                "X-Total-Pages": str(total_pages)
            }
        )
        
    except ValueError as e:
        logger.warning(f"Export validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        logger.error(f"Unexpected export error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during export")


# GCS Export Endpoint
@app.post("/export/{table_key}/gcs")
@limiter.limit("50/minute")
async def export_table_to_gcs(
    request: Request,
    table_key: str,
    export_request: GCSExportRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Export a single page of table data to Google Cloud Storage.
    """
    if table_key not in TABLE_REGISTRY:
        logger.warning(f"Invalid table for GCS export: {table_key}")
        raise HTTPException(
            status_code=404,
            detail=f"Table '{table_key}' not found. Available: {list(TABLE_REGISTRY.keys())}"
        )
    
    user_id = current_user.get("sub", "unknown")
    logger.info(
        f"GCS export by user={user_id} | "
        f"table={table_key} | page={export_request.page}/{export_request.total_pages} | "
        f"bucket={export_request.bucket_name}"
    )
    
    try:
        result = dump_table_to_gcs(
            table_key=table_key,
            bucket_name=export_request.bucket_name,
            page_number=export_request.page,
            total_pages=export_request.total_pages,
            folder_prefix=export_request.folder_prefix
        )
        
        logger.info(
            f"✅ GCS export succeeded: {result['gcs_uri']} | "
            f"{result['rows_exported']:,} rows"
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Export completed successfully",
                "export": result
            }
        )
        
    except ValueError as e:
        logger.warning(f"GCS export validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
        
    except PermissionError as e:
        logger.error(f"GCS permission denied: {str(e)}")
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions to write to GCS bucket"
        )
        
    except Exception as e:
        logger.error(f"Unexpected GCS export error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during GCS export")


# List Tables Endpoint
@app.get("/tables")
@limiter.limit("100/minute")
async def list_tables(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """List all available tables that can be exported."""
    tables = [
        {
            "key": key,
            "name": config["name"],
            "columns": config["columns"],
            "primary_key": config["primary_key"]
        }
        for key, config in TABLE_REGISTRY.items()
    ]
    
    return {
        "tables": tables,
        "count": len(tables)
    }