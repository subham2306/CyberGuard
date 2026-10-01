import cv2
import numpy as np
from typing import Dict, Any, List

class QRDecoder:
    """
    Robust Multi-Stage QR Code Decoder using OpenCV.
    Implements a fallback pipeline with resizing, grayscale, contrast enhancement, 
    thresholding, inversion, and rotation.
    """
    def __init__(self):
        self.cv_detector = cv2.QRCodeDetector()

    def decode_image(self, image_path_or_bytes) -> Dict[str, Any]:
        """
        Decodes a QR code from file path, numpy array, or file-like object.
        Returns:
            {
                'success': bool,
                'raw_content': str,
                'error': Optional[str]
            }
        """
        try:
            if isinstance(image_path_or_bytes, str):
                img = cv2.imread(image_path_or_bytes)
            elif isinstance(image_path_or_bytes, np.ndarray):
                img = image_path_or_bytes
            elif hasattr(image_path_or_bytes, 'read'):
                file_bytes = np.asarray(bytearray(image_path_or_bytes.read()), dtype=np.uint8)
                img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            else:
                return {'success': False, 'raw_content': '', 'error': 'Unsupported image input type'}

            if img is None:
                return {'success': False, 'raw_content': '', 'error': 'Could not read image file or buffer'}

            # Preprocessing Candidates Generator
            candidates = self._generate_candidates(img)

            for cand_name, cand_img in candidates:
                # Try single detect
                data, bbox, _ = self.cv_detector.detectAndDecode(cand_img)
                if data and len(data.strip()) > 0:
                    return {'success': True, 'raw_content': data.strip(), 'error': None}
                
                # Try multi detect as a fallback
                ret, decoded_info, points, _ = self.cv_detector.detectAndDecodeMulti(cand_img)
                if ret and decoded_info:
                    valid_texts = [info.strip() for info in decoded_info if info.strip()]
                    if valid_texts:
                        return {'success': True, 'raw_content': valid_texts[0], 'error': None}

            return {'success': False, 'raw_content': '', 'error': 'No QR code pattern detected in the image.'}

        except Exception as e:
            return {'success': False, 'raw_content': '', 'error': str(e)}

    def _generate_candidates(self, original_img: np.ndarray) -> List[tuple]:
        """Generates various preprocessed versions of the image to maximize decoding success."""
        candidates = []
        candidates.append(("original", original_img))
        
        # 1. Grayscale
        gray = cv2.cvtColor(original_img, cv2.COLOR_BGR2GRAY)
        candidates.append(("grayscale", gray))
        
        # 2. Resizing (Upscale & Downscale)
        for scale in [1.5, 2.0, 3.0, 0.5]:
            width = int(original_img.shape[1] * scale)
            height = int(original_img.shape[0] * scale)
            resized = cv2.resize(original_img, (width, height), interpolation=cv2.INTER_CUBIC)
            candidates.append((f"resized_{scale}x", resized))
            
            gray_resized = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
            candidates.append((f"grayscale_resized_{scale}x", gray_resized))
            
            # Otsu on resized
            _, thresh_resized = cv2.threshold(gray_resized, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            candidates.append((f"otsu_resized_{scale}x", thresh_resized))
        
        # 3. Contrast Enhancement (CLAHE)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
        contrast_enhanced = clahe.apply(gray)
        candidates.append(("clahe", contrast_enhanced))
        
        # 4. Thresholding
        _, otsu_thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        candidates.append(("otsu", otsu_thresh))
        
        adaptive_thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        candidates.append(("adaptive_gaussian", adaptive_thresh))
        
        # 5. Inversion (Some QR codes have white foreground and black background)
        inverted = cv2.bitwise_not(gray)
        candidates.append(("inverted", inverted))
        _, inv_otsu = cv2.threshold(inverted, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        candidates.append(("inverted_otsu", inv_otsu))

        # 6. Rotation (90, 180, 270)
        candidates.append(("rotated_90", cv2.rotate(original_img, cv2.ROTATE_90_CLOCKWISE)))
        candidates.append(("rotated_180", cv2.rotate(original_img, cv2.ROTATE_180)))
        candidates.append(("rotated_270", cv2.rotate(original_img, cv2.ROTATE_90_COUNTERCLOCKWISE)))
        
        return candidates
