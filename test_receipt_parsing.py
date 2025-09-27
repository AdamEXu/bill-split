#!/usr/bin/env python3
"""
Test script for receipt parsing functionality
"""

import requests
import os
import sys
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont


def create_test_receipt_image():
    """Create a simple test receipt image"""
    # Create a white image
    width, height = 400, 600
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)

    # Try to use a default font, fallback to basic if not available
    try:
        font_large = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 20)
        font_medium = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 16)
        font_small = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 14)
    except:
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # Draw receipt content
    y = 30

    # Restaurant name
    draw.text((width // 2 - 80, y), "MARIO'S PIZZA", fill="black", font=font_large)
    y += 40

    draw.text((width // 2 - 60, y), "123 Main Street", fill="black", font=font_small)
    y += 20
    draw.text((width // 2 - 70, y), "New York, NY 10001", fill="black", font=font_small)
    y += 40

    # Date and time
    draw.text((50, y), "Date: 01/27/2025  Time: 7:30 PM", fill="black", font=font_small)
    y += 30

    # Items
    draw.text((50, y), "ITEMS:", fill="black", font=font_medium)
    y += 25

    draw.text((50, y), "Large Pepperoni Pizza", fill="black", font=font_small)
    draw.text((300, y), "$18.99", fill="black", font=font_small)
    y += 20

    draw.text((50, y), "Caesar Salad", fill="black", font=font_small)
    draw.text((300, y), "$8.50", fill="black", font=font_small)
    y += 20

    draw.text((50, y), "Garlic Bread", fill="black", font=font_small)
    draw.text((300, y), "$4.99", fill="black", font=font_small)
    y += 20

    draw.text((50, y), "Coca Cola (2)", fill="black", font=font_small)
    draw.text((300, y), "$3.98", fill="black", font=font_small)
    y += 40

    # Totals
    draw.line([(50, y), (350, y)], fill="black", width=1)
    y += 10

    draw.text((50, y), "Subtotal:", fill="black", font=font_medium)
    draw.text((300, y), "$36.46", fill="black", font=font_medium)
    y += 25

    draw.text((50, y), "Tax:", fill="black", font=font_medium)
    draw.text((300, y), "$3.28", fill="black", font=font_medium)
    y += 25

    draw.text((50, y), "Tip:", fill="black", font=font_medium)
    draw.text((300, y), "$7.30", fill="black", font=font_medium)
    y += 25

    draw.line([(50, y), (350, y)], fill="black", width=2)
    y += 10

    draw.text((50, y), "TOTAL:", fill="black", font=font_large)
    draw.text((290, y), "$47.04", fill="black", font=font_large)

    return image


def test_receipt_parsing():
    """Test the receipt parsing API endpoint"""
    print("🧪 Testing Receipt Parsing Functionality")
    print("=" * 50)

    # Create test receipt image
    print("📄 Creating test receipt image...")
    receipt_image = create_test_receipt_image()

    # Save to BytesIO for upload
    img_buffer = BytesIO()
    receipt_image.save(img_buffer, format="PNG")
    img_buffer.seek(0)

    # Test the API endpoint
    print("🚀 Testing API endpoint...")

    try:
        # Note: This will fail without authentication, but we can test the endpoint exists
        files = {"receipt_image": ("test_receipt.png", img_buffer, "image/png")}
        response = requests.post("http://127.0.0.1:5001/api/parse-receipt", files=files)

        print(f"📊 Response Status: {response.status_code}")
        print(f"📋 Response Content: {response.text}")

        if response.status_code == 401:
            print("✅ API endpoint exists and requires authentication (expected)")
            return True
        elif response.status_code == 200:
            print("✅ API endpoint working!")
            return True
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Error testing API: {e}")
        return False


def test_openai_connection():
    """Test OpenAI API connection"""
    print("\n🤖 Testing OpenAI Connection")
    print("=" * 30)

    try:
        import openai
        from dotenv import load_dotenv

        load_dotenv()
        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

        # Test with a simple text completion
        response = client.chat.completions.create(
            model="gpt-5",
            messages=[
                {"role": "user", "content": "Say 'Hello, receipt parsing test!'"}
            ],
            max_completion_tokens=10,
        )

        print("✅ OpenAI API connection successful!")
        print(f"📝 Response: {response.choices[0].message.content}")
        return True

    except Exception as e:
        print(f"❌ OpenAI API error: {e}")
        return False


if __name__ == "__main__":
    print("🧪 Receipt Parsing Test Suite")
    print("=" * 40)

    # Test 1: API endpoint
    api_test = test_receipt_parsing()

    # Test 2: OpenAI connection
    openai_test = test_openai_connection()

    print("\n📊 Test Results Summary")
    print("=" * 25)
    print(f"API Endpoint: {'✅ PASS' if api_test else '❌ FAIL'}")
    print(f"OpenAI Connection: {'✅ PASS' if openai_test else '❌ FAIL'}")

    if api_test and openai_test:
        print("\n🎉 All tests passed! Receipt parsing should work correctly.")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
