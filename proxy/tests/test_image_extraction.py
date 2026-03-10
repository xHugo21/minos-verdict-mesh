"""Tests for base64 image extraction from various API formats"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.llm_request_guard import LLMRequestGuard


def test_extract_openai_format():
    """Test extraction of base64 images from OpenAI/GPT-4 Vision format"""
    detector = LLMRequestGuard()
    
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What's in this image?"},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
                        }
                    }
                ]
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    assert len(images) == 1
    assert images[0]["mime_type"] == "image/png"
    assert images[0]["source"] == "openai"
    assert "iVBORw0KGgo" in images[0]["data"]


def test_extract_claude_format():
    """Test extraction of base64 images from Anthropic Claude format"""
    detector = LLMRequestGuard()
    
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/jpeg",
                            "data": "base64_image_data_here"
                        }
                    },
                    {"type": "text", "text": "Analyze this"}
                ]
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    assert len(images) == 1
    assert images[0]["mime_type"] == "image/jpeg"
    assert images[0]["source"] == "claude"
    assert images[0]["data"] == "base64_image_data_here"


def test_extract_copilot_format():
    """Test extraction of base64 images from GitHub Copilot format"""
    detector = LLMRequestGuard()
    
    payload = {
        "messages": [
            {
                "role": "user",
                "content": "Check this image",
                "attachments": [
                    {
                        "type": "image",
                        "data": "copilot_base64_data",
                        "mime_type": "image/png"
                    }
                ]
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    assert len(images) == 1
    assert images[0]["mime_type"] == "image/png"
    assert images[0]["source"] == "copilot"
    assert images[0]["data"] == "copilot_base64_data"


def test_extract_gemini_format():
    """Test extraction of base64 images from Google Gemini format"""
    detector = LLMRequestGuard()
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": "What is this?"},
                    {
                        "inline_data": {
                            "mime_type": "image/jpeg",
                            "data": "gemini_base64_data"
                        }
                    }
                ]
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    assert len(images) == 1
    assert images[0]["mime_type"] == "image/jpeg"
    assert images[0]["source"] == "gemini"
    assert images[0]["data"] == "gemini_base64_data"


def test_extract_multiple_images():
    """Test extraction of multiple images from a single request"""
    detector = LLMRequestGuard()
    
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Compare these images"},
                    {
                        "type": "image_url",
                        "image_url": {"url": "data:image/png;base64,first_image"}
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": "data:image/jpeg;base64,second_image"}
                    }
                ]
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    assert len(images) == 2
    assert images[0]["data"] == "first_image"
    assert images[1]["data"] == "second_image"


def test_extract_no_images():
    """Test that extraction returns empty list when no images present"""
    detector = LLMRequestGuard()
    
    payload = {
        "messages": [
            {
                "role": "user",
                "content": "Just text, no images"
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    assert len(images) == 0


def test_extract_malformed_data():
    """Test that extraction handles malformed data gracefully"""
    detector = LLMRequestGuard()
    
    # Missing required fields
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {}  # Missing url field
                    }
                ]
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    # Should not crash, just return empty list
    assert len(images) == 0


def test_extract_url_reference():
    """Test that URL references (not base64) are ignored"""
    detector = LLMRequestGuard()
    
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": "https://example.com/image.png"  # HTTP URL, not data URL
                        }
                    }
                ]
            }
        ]
    }
    
    images = detector._extract_base64_images(payload)
    
    # Should ignore HTTP URLs (only process data URLs with base64)
    assert len(images) == 0


if __name__ == "__main__":
    print("Running image extraction tests...")
    
    test_extract_openai_format()
    print("✓ OpenAI format extraction")
    
    test_extract_claude_format()
    print("✓ Claude format extraction")
    
    test_extract_copilot_format()
    print("✓ Copilot format extraction")
    
    test_extract_gemini_format()
    print("✓ Gemini format extraction")
    
    test_extract_multiple_images()
    print("✓ Multiple images extraction")
    
    test_extract_no_images()
    print("✓ No images handling")
    
    test_extract_malformed_data()
    print("✓ Malformed data handling")
    
    test_extract_url_reference()
    print("✓ URL reference handling")
    
    print("\n✅ All tests passed!")
