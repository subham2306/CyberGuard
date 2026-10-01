from playwright.sync_api import sync_playwright

def test_qr_scanner():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # Navigate to the locally running app
        page.goto("http://127.0.0.1:8081/")
        
        # Click the QR Scanner tab
        page.click('[data-target="qr-panel"]')
        
        # Wait for the panel to become active
        page.wait_for_selector('#qr-panel.active-section')
        
        # Upload a known-good QR code
        page.set_input_files('#qrFileInput', 'tests/qr_samples/benign_1.png')
        
        # Ensure the preview is populated
        page.wait_for_selector('#qrPreviewContainer:not(.hidden)')
        
        # Ensure the analyze button is enabled
        assert not page.locator('#btnAnalyzeQr').is_disabled()
        
        with page.expect_response("**/predict-qr") as response_info:
            # Click the Scan button
            page.click('#btnAnalyzeQr')
            
        response = response_info.value
        print(f"API Response Status: {response.status}")
        print(f"API Response JSON: {response.json()}")
        
        # Wait for loading to finish and results to appear
        page.wait_for_selector('#resultScreen:not(.hidden)', timeout=10000)
        
        # Read the extracted text
        extracted_text = page.locator('#extractedText').inner_text()
        print(f"EXTRACTED TEXT IN UI: {extracted_text}")
        
        if extracted_text == "https://wikipedia.org":
            print("SUCCESS! The frontend correctly requested, received, and rendered the QR payload.")
        else:
            print("FAILURE: Extracted text does not match expected URL.")
            
        browser.close()

if __name__ == "__main__":
    test_qr_scanner()
