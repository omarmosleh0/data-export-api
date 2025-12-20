import os
import json
import logging
from typing import Optional, Dict, Any, Generator
from datetime import datetime
from pathlib import Path
import sqlalchemy
from sqlalchemy import exc, text, quoted_name
from config import TABLE_REGISTRY
from dotenv import load_dotenv
import re
from google.cloud import storage
from google.cloud.exceptions import GoogleCloudError

load_dotenv()

logger = logging.getLogger(__name__)

# Validate SQL identifiers
def validate_identifier(name: str) -> bool:
    """
    Validate that a database identifier (table/column) is safe:
    - Non-empty
    - Max 63 chars (PostgreSQL limit)
    - Starts with letter/underscore
    - Contains only letters, digits, underscores
    """
    if not isinstance(name, str) or len(name) == 0 or len(name) > 63:
        return False
    return bool(re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name))

# SINGLETON ENGINE: Module-level variable
_engine = None

def init_db_engine():
    """
    Initialize the database engine ONCE at application startup.
    Thread-safe for Cloud Run's single-threaded model.
    """
    global _engine
    if _engine is not None:
        return _engine

    # Validate Cloud SQL config
    db_socket_path = os.environ.get('DB_SOCKET_PATH')
    if not db_socket_path:
        raise RuntimeError("DB_SOCKET_PATH must be set for Cloud SQL")
    
    # Dynamic pool sizing
    DEFAULT_POOL_SIZE = 10
    DEFAULT_MAX_OVERFLOW = 5
    
    pool_size = int(os.environ.get("DB_POOL_SIZE", DEFAULT_POOL_SIZE))
    max_overflow = int(os.environ.get("DB_MAX_OVERFLOW", DEFAULT_MAX_OVERFLOW))
    
    MAX_ALLOWED_POOL = 50
    pool_size = min(pool_size, MAX_ALLOWED_POOL)
    max_overflow = min(max_overflow, MAX_ALLOWED_POOL)
    
    logger.info(
        f"Initializing DB pool with size={pool_size}, "
        f"overflow={max_overflow}, pre_ping=True"
    )
    
    db_config = {
        'pool_size': pool_size,
        'max_overflow': max_overflow,
        'pool_timeout': 10,
        'pool_recycle': 1800,
        'pool_pre_ping': True,
        'connect_args': {
            'timeout': 10,
        }
    }

    _engine = sqlalchemy.create_engine(
        sqlalchemy.engine.url.URL.create(
            drivername="postgresql+pg8000",
            host=db_socket_path,
            username=os.environ.get('DB_USER'),
            password=os.environ.get('DB_PASS'),
            database=os.environ.get('DB_NAME'),
        ),
        **db_config
    )
    return _engine

def get_db_engine():
    """Get initialized engine. Must be called AFTER init_db_engine()."""
    if _engine is None:
        raise RuntimeError(
            "DB engine not initialized. "
            "Call init_db_engine() in a startup event first."
        )
    return _engine
    
def stream_table_jsonl(
    table_key: str,
    page_number: int = 1,
    total_pages: int = 10,
    safety_limit: int = 100_000
) -> Generator[str, None, None]:
    """
    Stream table data as JSONL using PK-range pagination.
    
    Args:
        table_key: Key in TABLE_REGISTRY
        page_number: Current page (1-indexed)
        total_pages: Total number of pages to divide table into
        safety_limit: Max rows per page to prevent OOM
        
    Yields:
        JSON strings with newline delimiters
    """
    # Validate table
    if table_key not in TABLE_REGISTRY:
        logger.warning(f"Blocked export attempt for invalid table: {table_key}")
        raise ValueError(f"Invalid table key: {table_key}")
    
    schema = TABLE_REGISTRY[table_key]
    table_name = schema["name"]
    columns = schema["columns"]
    pk = schema["primary_key"]
    
    # Validate BEFORE wrapping with quoted_name
    if not validate_identifier(table_name):
        raise ValueError(f"Invalid table name in registry: {table_name}")
    if not validate_identifier(pk):
        raise ValueError(f"Invalid primary key in registry: {pk}")
    for col in columns:
        if not validate_identifier(col):
            raise ValueError(f"Invalid column name in registry: {col}")

    # Safely quote all identifiers AFTER validation
    safe_table = quoted_name(table_name, quote=True)
    safe_pk = quoted_name(pk, quote=True)
    safe_columns = [quoted_name(col, quote=True) for col in columns]
    columns_csv = ", ".join(str(col) for col in safe_columns)
 
    engine = get_db_engine()
    
    # GET GLOBAL PK BOUNDARIES 
    try:
        with engine.connect() as conn:
            bounds_query = text(f"""
                SELECT 
                    MIN({safe_pk}) AS min_pk, 
                    MAX({safe_pk}) AS max_pk,
                    COUNT(*) AS total_rows
                FROM {safe_table}
            """)
            bounds = conn.execute(bounds_query).mappings().first()
            
            if not bounds or bounds["min_pk"] is None:
                logger.info(f"Table {table_name} is empty")
                return  # Yield nothing
            
            min_pk = bounds["min_pk"]
            max_pk = bounds["max_pk"]
            total_rows = bounds["total_rows"]
            
            logger.info(f"Table bounds: min={min_pk}, max={max_pk}, total_rows={total_rows}")
    
    except exc.SQLAlchemyError as e:
        logger.critical(f"Failed to get PK bounds for {table_key}: {str(e)}")
        raise RuntimeError("Could not determine pagination boundaries") from e
    
    # CALCULATE PAGE BOUNDARIES
    try:
        page_size = (max_pk - min_pk + 1) / total_pages
        page_start = min_pk + (page_number - 1) * page_size
        page_end = min_pk + page_number * page_size - 1
        
        # Handle numeric edge cases
        if isinstance(min_pk, int):
            page_start = int(page_start)
            page_end = int(page_end)
            
        logger.debug(f"Page {page_number}/{total_pages} range: {page_start} to {page_end}")
    except Exception as e:
        logger.error(f"Page boundary calculation failed: {str(e)}")
        raise ValueError("Invalid page parameters") from e
    
    # BUILD QUERY WITH PK RANGE
    query = text(f"""
        SELECT {columns_csv}
        FROM {safe_table}
        WHERE {safe_pk} BETWEEN :min_val AND :max_val
        ORDER BY {safe_pk} ASC
        LIMIT :safety_limit
    """)
    
    params = {
        "min_val": page_start,
        "max_val": page_end,
        "safety_limit": safety_limit
    }
    
    try:
        with engine.connect() as conn:
            result = conn.execution_options(stream_results=True).execute(query, params)
            row_count = 0
            logger.info(f"Starting page {page_number}/{total_pages} for {table_key}")
            
            for row in result:
                try:
                    yield json.dumps(
                        dict(zip(result.keys(), row)),
                        default=str,
                        ensure_ascii=False
                    ) + "\n"
                    row_count += 1
                except Exception as e:
                    logger.error(f"Row serialization failed: {str(e)}")
            
            logger.info(
                f"Completed page {page_number}/{total_pages}: "
                f"{row_count} rows (range: {page_start}-{page_end})"
            )
            
    except exc.SQLAlchemyError as e:
        logger.critical(f"DB query failed for page {page_number} of {table_key}: {str(e)}")
        raise RuntimeError("Database error during pagination") from e


###########################################################
# GCS EXPORT FUNCTION
###########################################################

def dump_table_to_gcs(
    table_key: str,
    bucket_name: str,
    page_number: int = 1,
    total_pages: int = 10,
    safety_limit: int = 100_000,
    folder_prefix: str = "exports"
) -> Dict[str, Any]:
    """
    Stream table data directly to Google Cloud Storage without local storage.
    
    Args:
        table_key: Key in TABLE_REGISTRY
        bucket_name: GCS bucket name (e.g., "data-exports")
        page_number: Current page (1-indexed)
        total_pages: Total pages to divide table into
        safety_limit: Max rows per page
        folder_prefix: Optional folder structure in bucket (default: "exports")
        
    Returns:
        Dict with export metadata:
        {
            "gcs_uri": "gs://bucket/path/to/file.jsonl",
            "public_url": "https://storage.googleapis.com/...",
            "rows_exported": 1234,
            "file_size_mb": 5.67,
            "page": 1,
            "total_pages": 10,
            "timestamp": "2025-12-20T10:30:00Z"
        }
        
    Raises:
        ValueError: Invalid table or parameters
        GoogleCloudError: GCS operation failed
        RuntimeError: Database or streaming error
    """
    
    # Validate inputs
    if table_key not in TABLE_REGISTRY:
        logger.warning(f"Invalid table key for GCS export: {table_key}")
        raise ValueError(f"Invalid table key: {table_key}")
    
    if not bucket_name:
        raise ValueError("bucket_name is required for GCS export")
    
    # Initialize GCS client
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        
        # Verify bucket exists and we have write access
        if not bucket.exists():
            raise ValueError(f"GCS bucket '{bucket_name}' does not exist or is not accessible")
            
    except GoogleCloudError as e:
        logger.error(f"Failed to initialize GCS client: {str(e)}")
        raise RuntimeError(f"GCS connection failed: {str(e)}") from e
    
    # Generate file path: exports/TABLE_NAME/YYYY-MM-DD/page_X_of_Y.jsonl
    timestamp = datetime.utcnow()
    date_partition = timestamp.strftime("%Y-%m-%d")
    
    blob_path = (
        f"{folder_prefix}/"
        f"{table_key}/"
        f"{date_partition}/"
        f"page_{page_number}_of_{total_pages}.jsonl"
    )
    
    blob = bucket.blob(blob_path)
    
    logger.info(f"Starting GCS export: {blob_path}")
    
    # Stream data directly to GCS
    rows_exported = 0
    bytes_written = 0
    
    try:
        # Open blob in write mode with buffering
        with blob.open(
            mode="w",
            content_type="application/x-ndjson",
            chunk_size=16 * 1024 * 1024  # 16MB chunks
        ) as gcs_file:
            
            # Get streaming generator from database
            data_stream = stream_table_jsonl(
                table_key=table_key,
                page_number=page_number,
                total_pages=total_pages,
                safety_limit=safety_limit
            )
            
            # Write each line directly to GCS
            for line in data_stream:
                gcs_file.write(line)
                rows_exported += 1
                bytes_written += len(line.encode('utf-8'))
                
                # Log progress every 10,000 rows
                if rows_exported % 10_000 == 0:
                    logger.info(
                        f"GCS export progress: {rows_exported:,} rows written "
                        f"({bytes_written / (1024**2):.2f} MB)"
                    )
        
        # File successfully written, get metadata
        blob.reload()
        
        file_size_mb = blob.size / (1024 ** 2) if blob.size else 0
        
        logger.info(
            f"✅ GCS export complete: {blob_path} | "
            f"{rows_exported:,} rows | {file_size_mb:.2f} MB"
        )
        
        # Return metadata
        return {
            "gcs_uri": f"gs://{bucket_name}/{blob_path}",
            "public_url": blob.public_url,
            "blob_name": blob_path,
            "bucket_name": bucket_name,
            "rows_exported": rows_exported,
            "file_size_mb": round(file_size_mb, 2),
            "page": page_number,
            "total_pages": total_pages,
            "timestamp": timestamp.isoformat() + "Z",
            "table_key": table_key,
            "content_type": "application/x-ndjson"
        }
        
    except GoogleCloudError as e:
        logger.error(f"GCS write failed for {blob_path}: {str(e)}")
        # Clean up partial file if it exists
        try:
            if blob.exists():
                blob.delete()
                logger.info(f"Cleaned up partial file: {blob_path}")
        except Exception:
            pass
        raise RuntimeError(f"Failed to write to GCS: {str(e)}") from e
        
    except Exception as e:
        logger.error(f"Unexpected error during GCS export: {str(e)}", exc_info=True)
        raise