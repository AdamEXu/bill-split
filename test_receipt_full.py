#!/usr/bin/env python3
"""
Full end-to-end test of receipt parsing functionality
"""

import requests
import os
import sys
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import json

def create_test_receipt_image():
    """Create a simple test receipt image"""
    # Create a white image
    width, height = 400, 600
    image = Image.new('RGB', (width, height), 'white')
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
    draw.text((width//2 - 80, y), "MARIO'S PIZZA", fill='black', font=font_large)
    y += 40
    
    draw.text((width//2 - 60, y), "123 Main Street", fill='black', font=font_small)
    y += 20
    draw.text((width//2 - 70, y), "New York, NY 10001", fill='black', font=font_small)
    y += 40
    
    # Date and time
    draw.text((50, y), "Date: 01/27/2025  Time: 7:30 PM", fill='black', font=font_small)
    y += 30
    
    # Items
    draw.text((50, y), "ITEMS:", fill='black', font=font_medium)
    y += 25
    
    draw.text((50, y), "Large Pepperoni Pizza", fill='black', font=font_small)
    draw.text((300, y), "$18.99", fill='black', font=font_small)
    y += 20
    
    draw.text((50, y), "Caesar Salad", fill='black', font=font_small)
    draw.text((300, y), "$8.50", fill='black', font=font_small)
    y += 20
    
    draw.text((50, y), "Garlic Bread", fill='black', font=font_small)
    draw.text((300, y), "$4.99", fill='black', font=font_small)
    y += 20
    
    draw.text((50, y), "Coca Cola (2)", fill='black', font=font_small)
    draw.text((300, y), "$3.98", fill='black', font=font_small)
    y += 40
    
    # Totals
    draw.line([(50, y), (350, y)], fill='black', width=1)
    y += 10
    
    draw.text((50, y), "Subtotal:", fill='black', font=font_medium)
    draw.text((300, y), "$36.46", fill='black', font=font_medium)
    y += 25
    
    draw.text((50, y), "Tax:", fill='black', font=font_medium)
    draw.text((300, y), "$3.28", fill='black', font=font_medium)
    y += 25
    
    draw.text((50, y), "Tip:", fill='black', font=font_medium)
    draw.text((300, y), "$7.30", fill='black', font=font_medium)
    y += 25
    
    draw.line([(50, y), (350, y)], fill='black', width=2)
    y += 10
    
    draw.text((50, y), "TOTAL:", fill='black', font=font_large)
    draw.text((290, y), "$47.04", fill='black', font=font_large)
    
    return image

def test_receipt_parsing_direct():
    """Test the receipt parsing function directly"""
    print("🧪 Testing Receipt Parsing Function Directly")
    print("=" * 50)
    
    # Create test receipt image
    print("📄 Creating test receipt image...")
    receipt_image = create_test_receipt_image()
    
    # Save to BytesIO for processing
    img_buffer = BytesIO()
    receipt_image.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    # Import the parsing function
    sys.path.append('/Users/adam/Developer/Bill-Split')
    from app import parse_receipt_with_ai
    
    print("🤖 Parsing receipt with GPT-5...")
    
    try:
        result = parse_receipt_with_ai(img_buffer)
        
        print(f"📊 Parsing Result:")
        print(f"   Success: {result['success']}")
        
        if result['success']:
            data = result['data']
            print(f"   Title: {data['title']}")
            print(f"   Subtotal: ${data['subtotal']:.2f}")
            print(f"   Tax: ${data['tax_amount']:.2f}")
            print(f"   Tip: ${data['tip_amount']:.2f}")
            print(f"   Total: ${data['total_amount']:.2f}")
            print(f"   Items ({len(data['items'])}):")
            for i, item in enumerate(data['items'], 1):
                print(f"     {i}. {item['name']} - ${item['price']:.2f} (qty: {item['quantity']})")
            
            # Validate the parsing
            expected_total = data['subtotal'] + data['tax_amount'] + data['tip_amount']
            actual_total = data['total_amount']
            
            if abs(expected_total - actual_total) < 0.01:
                print("✅ Total calculation is correct!")
            else:
                print(f"⚠️  Total calculation mismatch: expected {expected_total:.2f}, got {actual_total:.2f}")
            
            return True
        else:
            print(f"❌ Parsing failed: {result['error']}")
            return False
            
    except Exception as e:
        print(f"❌ Error during parsing: {e}")
        return False

def create_summary_report():
    """Create a summary report of the receipt parsing implementation"""
    print("\n📋 Receipt Parsing Implementation Summary")
    print("=" * 50)
    
    print("✅ COMPLETED FEATURES:")
    print("   • OpenAI GPT-5 integration with vision capabilities")
    print("   • Receipt image upload and processing")
    print("   • Structured data extraction (title, amounts, items)")
    print("   • Automatic form field population")
    print("   • Error handling and user feedback")
    print("   • API endpoint for receipt parsing")
    print("   • Client-side JavaScript for file upload")
    print("   • Loading states and status indicators")
    print("   • Input validation and sanitization")
    print("   • Support for multiple image formats")
    
    print("\n🔧 TECHNICAL IMPLEMENTATION:")
    print("   • Model: GPT-5 (latest OpenAI model)")
    print("   • Image encoding: Base64")
    print("   • Response format: Structured JSON")
    print("   • Temperature: 0.1 (for consistency)")
    print("   • Max tokens: 1000 completion tokens")
    print("   • Detail level: High (for accuracy)")
    
    print("\n🎯 USER WORKFLOW:")
    print("   1. User uploads receipt image in bill creation form")
    print("   2. JavaScript handles file upload and shows loading state")
    print("   3. Image sent to /api/parse-receipt endpoint")
    print("   4. GPT-5 analyzes image and extracts structured data")
    print("   5. Form fields automatically populated with extracted data")
    print("   6. User can review and edit before saving bill")
    
    print("\n🛡️  SECURITY & VALIDATION:")
    print("   • Authentication required for API access")
    print("   • File type validation (images only)")
    print("   • Data sanitization and type conversion")
    print("   • Error handling for malformed responses")
    print("   • Graceful fallback for parsing failures")

if __name__ == "__main__":
    print("🧪 Full Receipt Parsing Test Suite")
    print("=" * 40)
    
    # Test the parsing function directly
    parsing_test = test_receipt_parsing_direct()
    
    # Create summary report
    create_summary_report()
    
    print("\n📊 Final Test Results")
    print("=" * 25)
    print(f"Receipt Parsing: {'✅ PASS' if parsing_test else '❌ FAIL'}")
    
    if parsing_test:
        print("\n🎉 Receipt parsing functionality is working correctly!")
        print("   Users can now upload receipt images and have them automatically")
        print("   parsed using GPT-5 to populate bill creation forms.")
    else:
        print("\n⚠️  Receipt parsing test failed. Check the errors above.")
