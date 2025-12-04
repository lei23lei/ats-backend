"""Cloudinary service for image uploads"""
import os
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

# Cloudinary configuration - lazy initialization
_configured = False


def configure_cloudinary():
    """Configure Cloudinary with credentials from environment variables"""
    global _configured
    if not _configured:
        cloudinary.config(
            cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
            api_key=os.getenv("CLOUDINARY_API_KEY"),
            api_secret=os.getenv("CLOUDINARY_API_SECRET"),
            secure=True  # Use HTTPS
        )
        _configured = True


async def upload_image(file_content: bytes, folder: str = "avatars", public_id: Optional[str] = None) -> dict:
    """
    Upload an image to Cloudinary
    
    Args:
        file_content: The image file content as bytes
        folder: The folder in Cloudinary to store the image (default: "avatars")
        public_id: Optional custom public ID for the image
    
    Returns:
        dict: Cloudinary upload response containing 'secure_url' and other metadata
    
    Raises:
        ValueError: If Cloudinary is not configured
        Exception: If upload fails
    """
    configure_cloudinary()
    
    # Validate configuration
    if not os.getenv("CLOUDINARY_CLOUD_NAME") or not os.getenv("CLOUDINARY_API_KEY") or not os.getenv("CLOUDINARY_API_SECRET"):
        raise ValueError(
            "Cloudinary configuration missing. Please set CLOUDINARY_CLOUD_NAME, "
            "CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET in .env"
        )
    
    # Upload options
    upload_options = {
        "folder": folder,
        "resource_type": "image",
        "overwrite": True,  # Overwrite if file with same public_id exists
    }
    
    # Add transformations for optimization
    # For avatars/icons: smaller size (256x256) is sufficient and reduces file size significantly
    upload_options["transformation"] = [
        {"width": 256, "height": 256, "crop": "fill", "gravity": "face"},  # Square crop, focus on face - optimized for avatars
        {"quality": "auto"},  # Auto quality optimization (Cloudinary optimizes based on image content)
        {"format": "auto"},  # Auto format (webp when supported - much smaller file size)
    ]
    
    if public_id:
        upload_options["public_id"] = public_id
    
    try:
        # Upload file content
        result = cloudinary.uploader.upload(
            file_content,
            **upload_options
        )
        return result
    except Exception as e:
        raise Exception(f"Failed to upload image to Cloudinary: {str(e)}")


async def delete_image(public_id: str) -> dict:
    """
    Delete an image from Cloudinary
    
    Args:
        public_id: The public ID of the image to delete
    
    Returns:
        dict: Cloudinary deletion response
    """
    configure_cloudinary()
    
    try:
        result = cloudinary.uploader.destroy(public_id)
        return result
    except Exception as e:
        raise Exception(f"Failed to delete image from Cloudinary: {str(e)}")
