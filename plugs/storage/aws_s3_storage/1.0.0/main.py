# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
AWS S3 Storage Plug - Enterprise cloud storage
Provides comprehensive S3 operations with security, encryption, and lifecycle management.
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import json
import base64
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
import mimetypes
import os

logger = logging.getLogger(__name__)

def process(ctx: dict, cfg: dict) -> dict:
    """
    Main plugin entry point for AWS S3 operations.
    
    Args:
        ctx: Pipe context containing operation parameters
        cfg: Plug configuration including AWS credentials
        
    Returns:
        Updated context with operation results
    """
    try:
        # Initialize S3 client
        client = S3Client(cfg)
        
        # Get operation from context
        operation = ctx.get('operation', 'list_objects')
        bucket = ctx.get('bucket')
        
        result = None
        
        # Bucket operations
        if operation == 'list_buckets':
            result = client.list_buckets()
        elif operation == 'create_bucket':
            result = client.create_bucket(bucket, ctx.get('region'), ctx.get('bucket_config'))
        elif operation == 'delete_bucket':
            result = client.delete_bucket(bucket, ctx.get('force', False))
        elif operation == 'get_bucket_info':
            result = client.get_bucket_info(bucket)
            
        # Object operations
        elif operation == 'list_objects':
            result = client.list_objects(
                bucket, 
                ctx.get('prefix'), 
                ctx.get('delimiter'),
                ctx.get('max_keys', 1000)
            )
        elif operation == 'get_object':
            result = client.get_object(bucket, ctx.get('key'), ctx.get('download_path'))
        elif operation == 'put_object':
            result = client.put_object(
                bucket, 
                ctx.get('key'), 
                ctx.get('body'), 
                ctx.get('file_path'),
                ctx.get('content_type'),
                ctx.get('metadata'),
                ctx.get('encryption')
            )
        elif operation == 'delete_object':
            result = client.delete_object(bucket, ctx.get('key'))
        elif operation == 'copy_object':
            result = client.copy_object(
                ctx.get('source_bucket'),
                ctx.get('source_key'),
                bucket,
                ctx.get('key'),
                ctx.get('metadata')
            )
        elif operation == 'get_object_metadata':
            result = client.get_object_metadata(bucket, ctx.get('key'))
            
        # URL operations
        elif operation == 'generate_presigned_url':
            result = client.generate_presigned_url(
                bucket,
                ctx.get('key'),
                ctx.get('expiration', 3600),
                ctx.get('method', 'GET')
            )
        elif operation == 'generate_upload_url':
            result = client.generate_presigned_post(
                bucket,
                ctx.get('key'),
                ctx.get('expiration', 3600),
                ctx.get('conditions')
            )
            
        # Batch operations
        elif operation == 'bulk_delete':
            result = client.bulk_delete(bucket, ctx.get('keys'))
        elif operation == 'sync_directory':
            result = client.sync_directory(
                ctx.get('local_path'),
                bucket,
                ctx.get('s3_prefix', ''),
                ctx.get('delete', False)
            )
            
        else:
            raise ValueError(f"Unsupported operation: {operation}")
        
        # Store results in context
        ctx['s3_result'] = result
        ctx['s3_status'] = 'success'
        
        logger.info(f"S3 {operation} operation completed successfully")
        return ctx
        
    except Exception as e:
        logger.error(f"S3 operation failed: {str(e)}")
        ctx['s3_result'] = None
        ctx['s3_status'] = 'error'
        ctx['s3_error'] = str(e)
        return ctx


class S3Client:
    """
    Enterprise AWS S3 client with security and error handling.
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.region = config.get('region', 'us-east-1')
        
        # Initialize boto3 client
        session_config = {}
        
        if config.get('aws_access_key_id'):
            session_config['aws_access_key_id'] = config['aws_access_key_id']
            session_config['aws_secret_access_key'] = config['aws_secret_access_key']
        
        if config.get('aws_session_token'):
            session_config['aws_session_token'] = config['aws_session_token']
        
        if config.get('profile'):
            session = boto3.Session(profile_name=config['profile'])
            self.s3_client = session.client('s3', region_name=self.region)
        else:
            self.s3_client = boto3.client('s3', region_name=self.region, **session_config)
        
        # Default encryption settings
        self.default_encryption = config.get('default_encryption', 'AES256')
    
    # Bucket operations
    def list_buckets(self) -> Dict[str, Any]:
        """List all S3 buckets."""
        try:
            response = self.s3_client.list_buckets()
            return {
                'buckets': response.get('Buckets', []),
                'owner': response.get('Owner'),
                'total_count': len(response.get('Buckets', []))
            }
        except ClientError as e:
            raise Exception(f"Failed to list buckets: {str(e)}")
    
    def create_bucket(self, bucket_name: str, region: Optional[str] = None, 
                     bucket_config: Optional[Dict] = None) -> Dict[str, Any]:
        """Create a new S3 bucket."""
        try:
            create_args = {'Bucket': bucket_name}
            
            # Add region configuration for non-us-east-1 regions
            if region and region != 'us-east-1':
                create_args['CreateBucketConfiguration'] = {'LocationConstraint': region}
            
            response = self.s3_client.create_bucket(**create_args)
            
            # Apply additional bucket configurations
            if bucket_config:
                if bucket_config.get('versioning'):
                    self.s3_client.put_bucket_versioning(
                        Bucket=bucket_name,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )
                
                if bucket_config.get('encryption'):
                    self.s3_client.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration={
                            'Rules': [{
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': self.default_encryption
                                }
                            }]
                        }
                    )
            
            return {
                'bucket': bucket_name,
                'location': response.get('Location'),
                'success': True
            }
        except ClientError as e:
            raise Exception(f"Failed to create bucket {bucket_name}: {str(e)}")
    
    def delete_bucket(self, bucket_name: str, force: bool = False) -> Dict[str, Any]:
        """Delete an S3 bucket."""
        try:
            if force:
                # Delete all objects first
                self._empty_bucket(bucket_name)
            
            self.s3_client.delete_bucket(Bucket=bucket_name)
            return {'bucket': bucket_name, 'success': True}
        except ClientError as e:
            raise Exception(f"Failed to delete bucket {bucket_name}: {str(e)}")
    
    def get_bucket_info(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket information and metadata."""
        try:
            info = {'bucket': bucket_name}
            
            # Get bucket location
            location_response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            info['region'] = location_response.get('LocationConstraint') or 'us-east-1'
            
            # Get versioning status
            try:
                versioning_response = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                info['versioning'] = versioning_response.get('Status', 'Disabled')
            except ClientError:
                info['versioning'] = 'Disabled'
            
            # Get encryption configuration
            try:
                encryption_response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                info['encryption'] = encryption_response.get('ServerSideEncryptionConfiguration')
            except ClientError:
                info['encryption'] = None
            
            return info
        except ClientError as e:
            raise Exception(f"Failed to get bucket info for {bucket_name}: {str(e)}")
    
    # Object operations
    def list_objects(self, bucket_name: str, prefix: Optional[str] = None,
                    delimiter: Optional[str] = None, max_keys: int = 1000) -> Dict[str, Any]:
        """List objects in an S3 bucket."""
        try:
            list_args = {
                'Bucket': bucket_name,
                'MaxKeys': max_keys
            }
            
            if prefix:
                list_args['Prefix'] = prefix
            if delimiter:
                list_args['Delimiter'] = delimiter
            
            response = self.s3_client.list_objects_v2(**list_args)
            
            return {
                'objects': response.get('Contents', []),
                'common_prefixes': response.get('CommonPrefixes', []),
                'total_count': response.get('KeyCount', 0),
                'is_truncated': response.get('IsTruncated', False),
                'next_token': response.get('NextContinuationToken')
            }
        except ClientError as e:
            raise Exception(f"Failed to list objects in {bucket_name}: {str(e)}")
    
    def get_object(self, bucket_name: str, key: str, download_path: Optional[str] = None) -> Dict[str, Any]:
        """Get an object from S3."""
        try:
            if download_path:
                # Download to file
                self.s3_client.download_file(bucket_name, key, download_path)
                return {
                    'key': key,
                    'download_path': download_path,
                    'success': True
                }
            else:
                # Get object content
                response = self.s3_client.get_object(Bucket=bucket_name, Key=key)
                content = response['Body'].read()
                
                return {
                    'key': key,
                    'content': base64.b64encode(content).decode('utf-8'),
                    'content_type': response.get('ContentType'),
                    'content_length': response.get('ContentLength'),
                    'last_modified': response.get('LastModified'),
                    'metadata': response.get('Metadata', {})
                }
        except ClientError as e:
            raise Exception(f"Failed to get object {key} from {bucket_name}: {str(e)}")
    
    def put_object(self, bucket_name: str, key: str, body: Optional[str] = None,
                  file_path: Optional[str] = None, content_type: Optional[str] = None,
                  metadata: Optional[Dict] = None, encryption: Optional[str] = None) -> Dict[str, Any]:
        """Put an object to S3."""
        try:
            put_args = {
                'Bucket': bucket_name,
                'Key': key
            }
            
            if file_path:
                # Upload from file
                if not content_type:
                    content_type, _ = mimetypes.guess_type(file_path)
                
                if content_type:
                    put_args['ContentType'] = content_type
                
                if metadata:
                    put_args['Metadata'] = metadata
                
                if encryption or self.default_encryption:
                    put_args['ServerSideEncryption'] = encryption or self.default_encryption
                
                self.s3_client.upload_file(file_path, bucket_name, key, ExtraArgs=put_args)
                
                return {
                    'key': key,
                    'file_path': file_path,
                    'success': True
                }
            else:
                # Upload from body content
                if body:
                    put_args['Body'] = body
                
                if content_type:
                    put_args['ContentType'] = content_type
                
                if metadata:
                    put_args['Metadata'] = metadata
                
                if encryption or self.default_encryption:
                    put_args['ServerSideEncryption'] = encryption or self.default_encryption
                
                response = self.s3_client.put_object(**put_args)
                
                return {
                    'key': key,
                    'etag': response.get('ETag'),
                    'success': True
                }
        except ClientError as e:
            raise Exception(f"Failed to put object {key} to {bucket_name}: {str(e)}")
    
    def delete_object(self, bucket_name: str, key: str) -> Dict[str, Any]:
        """Delete an object from S3."""
        try:
            self.s3_client.delete_object(Bucket=bucket_name, Key=key)
            return {'key': key, 'success': True}
        except ClientError as e:
            raise Exception(f"Failed to delete object {key} from {bucket_name}: {str(e)}")
    
    def copy_object(self, source_bucket: str, source_key: str, dest_bucket: str,
                   dest_key: str, metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Copy an object within S3."""
        try:
            copy_source = {'Bucket': source_bucket, 'Key': source_key}
            copy_args = {
                'CopySource': copy_source,
                'Bucket': dest_bucket,
                'Key': dest_key
            }
            
            if metadata:
                copy_args['Metadata'] = metadata
                copy_args['MetadataDirective'] = 'REPLACE'
            
            response = self.s3_client.copy_object(**copy_args)
            
            return {
                'source': f"{source_bucket}/{source_key}",
                'destination': f"{dest_bucket}/{dest_key}",
                'etag': response.get('CopyObjectResult', {}).get('ETag'),
                'success': True
            }
        except ClientError as e:
            raise Exception(f"Failed to copy object: {str(e)}")
    
    def get_object_metadata(self, bucket_name: str, key: str) -> Dict[str, Any]:
        """Get object metadata without downloading content."""
        try:
            response = self.s3_client.head_object(Bucket=bucket_name, Key=key)
            
            return {
                'key': key,
                'content_type': response.get('ContentType'),
                'content_length': response.get('ContentLength'),
                'last_modified': response.get('LastModified'),
                'etag': response.get('ETag'),
                'metadata': response.get('Metadata', {}),
                'server_side_encryption': response.get('ServerSideEncryption')
            }
        except ClientError as e:
            raise Exception(f"Failed to get metadata for {key} in {bucket_name}: {str(e)}")
    
    # URL operations
    def generate_presigned_url(self, bucket_name: str, key: str, expiration: int = 3600,
                              method: str = 'GET') -> Dict[str, Any]:
        """Generate a presigned URL for S3 object access."""
        try:
            client_method = 'get_object' if method.upper() == 'GET' else 'put_object'
            
            url = self.s3_client.generate_presigned_url(
                ClientMethod=client_method,
                Params={'Bucket': bucket_name, 'Key': key},
                ExpiresIn=expiration
            )
            
            return {
                'url': url,
                'expiration': expiration,
                'method': method.upper(),
                'key': key
            }
        except ClientError as e:
            raise Exception(f"Failed to generate presigned URL: {str(e)}")
    
    def generate_presigned_post(self, bucket_name: str, key: str, expiration: int = 3600,
                               conditions: Optional[List] = None) -> Dict[str, Any]:
        """Generate presigned POST data for direct uploads."""
        try:
            response = self.s3_client.generate_presigned_post(
                Bucket=bucket_name,
                Key=key,
                ExpiresIn=expiration,
                Conditions=conditions or []
            )
            
            return response
        except ClientError as e:
            raise Exception(f"Failed to generate presigned POST: {str(e)}")
    
    # Batch operations
    def bulk_delete(self, bucket_name: str, keys: List[str]) -> Dict[str, Any]:
        """Delete multiple objects in a single request."""
        try:
            delete_objects = [{'Key': key} for key in keys]
            
            response = self.s3_client.delete_objects(
                Bucket=bucket_name,
                Delete={'Objects': delete_objects}
            )
            
            return {
                'deleted': response.get('Deleted', []),
                'errors': response.get('Errors', []),
                'success_count': len(response.get('Deleted', [])),
                'error_count': len(response.get('Errors', []))
            }
        except ClientError as e:
            raise Exception(f"Failed to bulk delete objects: {str(e)}")
    
    def sync_directory(self, local_path: str, bucket_name: str, s3_prefix: str = '',
                      delete: bool = False) -> Dict[str, Any]:
        """Sync a local directory to S3."""
        try:
            uploaded = []
            errors = []
            
            for root, dirs, files in os.walk(local_path):
                for file in files:
                    local_file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(local_file_path, local_path)
                    s3_key = os.path.join(s3_prefix, relative_path).replace('\\', '/')
                    
                    try:
                        self.s3_client.upload_file(local_file_path, bucket_name, s3_key)
                        uploaded.append({'local': local_file_path, 's3_key': s3_key})
                    except Exception as e:
                        errors.append({'file': local_file_path, 'error': str(e)})
            
            return {
                'uploaded': uploaded,
                'errors': errors,
                'upload_count': len(uploaded),
                'error_count': len(errors)
            }
        except Exception as e:
            raise Exception(f"Failed to sync directory: {str(e)}")
    
    def _empty_bucket(self, bucket_name: str):
        """Empty all objects from a bucket."""
        paginator = self.s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name)
        
        for page in pages:
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                self.s3_client.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': objects}
                )


# Plug metadata
plug_metadata = {
    "name": "aws_s3_storage",
    "version": "1.0.0",
    "description": "Enterprise AWS S3 cloud storage integration with security and lifecycle management",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "storage",
    "tags": ["aws", "s3", "storage", "cloud", "backup", "cdn"],
    "requirements": ["boto3", "botocore"]
}