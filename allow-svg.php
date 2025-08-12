<?php

declare(strict_types=1);

/**
 * Plugin Name: Allow SVG
 * Description: SVG support for WordPress
 * Version: 1.0.1
 * Author: Roots
 * Author URI: https://roots.io
 * License: MIT
 * Text Domain: allow-svg
 * Requires at least: 5.9
 * Requires PHP: 8.2
 */

namespace AllowSvg;

if (! defined('ABSPATH')) {
    exit;
}

class SvgUploadHandler
{
    private readonly array $dangerousPatterns;

    /**
     * Initializes the plugin.
     */
    public function __construct()
    {
        $this->dangerousPatterns = [
            // Script tag patterns - including namespaced variants
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/<[\w:]+:script\b/i', // Namespaced script tags (e.g., svg:script)
            '/<\w+\s[^>]*script\w*\s*=/i', // Script attributes

            // JavaScript patterns
            '/javascript:/i',

            // Event handlers (comprehensive coverage)
            '/\bon\w+\s*=/i', // Event handlers like onclick, onload, etc.
            '/on[a-zA-Z]+\s*=/i', // Additional event handler patterns (onmouseover, onfocus, etc.)

            // Dangerous tags and elements
            '/<iframe\b/i',
            '/<object\b/i',
            '/<embed\b/i',
            '/<[\w:]*foreignobject\b/i', // Foreign objects (including namespaced)

            // External references
            '/<use\s+href\s*=\s*["\']?https?:/i',
            '/<image\s+href\s*=\s*["\']?https?:/i',
            '/xlink:href\s*=\s*["\']?https?:/i',

            // Style-related threats
            '/<style\b[^>]*>.*?<\/style>/is', // Style tags can contain CSS expressions
            '/<[\w:]+:style\b[^>]*>.*?<\/[\w:]+:style>/is', // Namespaced style tags
            '/expression\s*\(/i', // CSS expressions
            '/@import/i', // CSS imports
            '/url\s*\(\s*["\']?javascript:/i', // CSS url() with javascript
            '/style\s*=\s*["\'][^"\']*expression\s*\(/i', // Inline style expressions
            '/style\s*=\s*["\'][^"\']*javascript:/i', // Inline style javascript URLs
            '/behavior\s*:/i', // IE CSS behaviors

            // Data URL threats
            '/data:\s*[^,]*(script|javascript)/i', // Data URLs with scripts/javascript
            '/data:\s*text\/html/i', // Data URLs with HTML content
            '/href\s*=\s*["\']?data:.*base64/i', // Block base64-encoded data in href

            // XML/DTD threats (XXE and entity bomb protection)
            '/<!DOCTYPE\b/i', // DOCTYPE declarations
            '/<!ENTITY\b/i', // Entity declarations
            '/&\w+;/', // Entity references
            '/%\w+;/', // Parameter entity references

            // CDATA sections that might contain malicious content
            '/<\!\[CDATA\[.*?(script|javascript).*?\]\]>/is',

            // Additional obfuscation patterns
            '/\\\\u[0-9a-f]{4}/i', // Unicode escapes
            '/\\\\x[0-9a-f]{2}/i', // Hex escapes
            '/eval\s*\(/i', // eval() calls
            '/setTimeout\s*\(/i', // setTimeout calls
            '/setInterval\s*\(/i', // setInterval calls
            '/Function\s*\(/i', // Function constructor

            // Filter evasion patterns
            '/\\[0-9]{1,3}/', // Octal escapes
        ];
    }

    /**
     * Initializes the plugin hooks.
     */
    public function init(): void
    {
        add_filter('upload_mimes', [$this, 'addSvgMimeType']);
        add_filter('wp_check_filetype_and_ext', [$this, 'checkSvgFiletype'], 10, 5);
        add_filter('wp_handle_upload_prefilter', [$this, 'handleSvgUpload']);
        add_filter('wp_handle_sideload_prefilter', [$this, 'handleSvgUpload']);
        add_filter('wp_handle_upload', [$this, 'handleSvgUploadResult'], 10, 2);
        add_filter('wp_generate_attachment_metadata', [$this, 'generateSvgMetadata'], 10, 2);
        add_filter('getimagesize_mimes_to_exts', [$this, 'addSvgToImageSizeExts']);
        add_filter('wp_image_file_matches_image_mime', [$this, 'allowSvgImageMime'], 10, 3);
        add_filter('wp_calculate_image_srcset_meta', [$this, 'disableSvgSrcset'], 10, 4);
        add_action('add_attachment', [$this, 'validateExistingAttachment']);
    }

    /**
     * Adds SVG mime type to the list of allowed mime types.
     *
     * @param  array  $mimes  The list of allowed mime types.
     * @return array The updated list of allowed mime types.
     */
    public function addSvgMimeType(array $mimes): array
    {
        $mimes['svg'] = 'image/svg+xml';

        return $mimes;
    }

    /**
     * Checks if the file is an SVG file.
     *
     * @param  array  $data  The file data.
     * @param  string  $file  The file path.
     * @param  string  $filename  The file name.
     * @param  array  $mimes  The list of allowed mime types.
     * @param  string  $realMime  The real mime type of the file.
     * @return array The updated file data.
     */
    public function checkSvgFiletype(array $data, string $file, string $filename, ?array $mimes, ?string $realMime = null): array
    {
        $ext = pathinfo($filename, PATHINFO_EXTENSION);

        if ($ext !== 'svg') {
            return $data;
        }

        $data['ext'] = 'svg';
        $data['type'] = 'image/svg+xml';
        $data['proper_filename'] = $filename;

        return $data;
    }

    /**
     * Handles SVG file uploads.
     *
     * @param  array  $file  The file data.
     * @return array The updated file data.
     */
    public function handleSvgUpload(array $file): array
    {
        if (! isset($file['type']) || $file['type'] !== 'image/svg+xml') {
            return $file;
        }

        // Validate file extension
        if (isset($file['name'])) {
            $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if ($ext !== 'svg') {
                $file['error'] = 'Invalid file type. Only SVG files are allowed.';

                return $file;
            }
        }

        // Check file size limit (5MB maximum)
        if (isset($file['size']) && $file['size'] > 5 * 1024 * 1024) {
            $file['error'] = 'SVG file exceeds maximum size limit of 5MB.';

            return $file;
        }

        // Validate file path security
        $filePath = realpath($file['tmp_name']);
        if ($filePath === false || ! is_file($filePath)) {
            $file['error'] = 'Invalid file path.';

            return $file;
        }

        if (! $this->isSvgFile($filePath)) {
            $file['error'] = 'File is not a valid SVG.';

            return $file;
        }

        $content = file_get_contents($filePath);

        // Log upload attempt
        if (isset($file['name'])) {
            error_log(sprintf('SVG upload attempt: %s (size: %d bytes)', $file['name'], $file['size'] ?? 0));
        }

        if ($content === false || ! $this->isValidSvg($content)) {
            // Log security rejection
            if (isset($file['name'])) {
                error_log(sprintf('SVG file contains dangerous content and was rejected for security reasons: %s', $file['name']));
            }

            $file['error'] = 'SVG file contains dangerous content and was rejected for security reasons.';

            return $file;
        }

        return $file;
    }

    /**
     * Handles SVG file upload results.
     *
     * @param  array  $upload  The upload data.
     * @param  mixed  $context  The upload context.
     * @return array The updated upload data.
     */
    public function handleSvgUploadResult(array $upload, $context = null): array
    {
        if (! isset($upload['type']) || $upload['type'] !== 'image/svg+xml') {
            return $upload;
        }

        // Validate file path security
        $filePath = realpath($upload['file']);
        if ($filePath === false || ! is_file($filePath)) {
            return [
                'error' => 'Invalid file path.',
            ];
        }

        $content = file_get_contents($filePath);
        if ($content !== false && ! $this->isValidSvg($content)) {
            // Log security rejection
            error_log(sprintf('SVG file contains dangerous content and was rejected for security reasons: %s', $upload['file']));

            // Delete the uploaded file
            unlink($filePath);

            return [
                'error' => 'SVG file contains dangerous content and was rejected for security reasons.',
            ];
        }

        return $upload;
    }

    /**
     * Checks if the file is an SVG file.
     *
     * @param  string  $filePath  The file path.
     * @return bool True if the file is an SVG file, false otherwise.
     */
    private function isSvgFile(string $filePath): bool
    {
        if (! file_exists($filePath)) {
            return false;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            return false;
        }

        return str_contains($content, '<svg') && str_contains($content, '</svg>');
    }

    /**
     * Checks if the SVG content is valid.
     *
     * @param  string  $content  The SVG content.
     * @return bool True if the SVG content is valid, false otherwise.
     */
    public function isValidSvg(string $content): bool
    {
        if (empty($content)) {
            return false;
        }

        // Must be valid SVG structure
        if (! str_contains($content, '<svg') || ! str_contains($content, '</svg>')) {
            return false;
        }

        // Check for dangerous patterns
        foreach ($this->dangerousPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return false;
            }
        }

        // Additional checks for obfuscation and entity encoding
        $decodedContent = $this->decodeEntities($content);
        foreach ($this->dangerousPatterns as $pattern) {
            if (preg_match($pattern, $decodedContent)) {
                return false;
            }
        }

        // Check for Unicode and hex escapes in decoded content
        if (preg_match('/\\\\\\\\u[0-9a-f]{4}/i', $decodedContent) || preg_match('/\\\\\\\\x[0-9a-f]{2}/i', $decodedContent)) {
            return false;
        }

        // Additional XML parsing with disabled external entities for XXE protection
        if (! $this->isValidXml($content)) {
            return false;
        }

        return true;
    }

    /**
     * Decodes HTML entities and numeric character references to reveal obfuscated content.
     *
     * @param  string  $content  The content to decode.
     * @return string The decoded content.
     */
    private function decodeEntities(string $content): string
    {
        // Decode HTML entities
        $content = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Decode hexadecimal numeric character references
        $content = preg_replace_callback('/&#x([0-9a-f]+);/i', function ($matches) {
            $codepoint = hexdec($matches[1]);

            return $codepoint <= 0x10FFFF ? mb_chr($codepoint, 'UTF-8') : '';
        }, $content);

        // Decode decimal numeric character references
        $content = preg_replace_callback('/&#([0-9]+);/i', function ($matches) {
            $codepoint = (int) $matches[1];

            return $codepoint <= 0x10FFFF ? mb_chr($codepoint, 'UTF-8') : '';
        }, $content);

        return $content;
    }

    /**
     * Checks if the XML content is valid.
     *
     * @param  string  $content  The XML content.
     * @return bool True if the XML content is valid, false otherwise.
     */
    private function isValidXml(string $content): bool
    {
        $originalInternalErrors = libxml_use_internal_errors(true);

        // Clear any previous errors
        libxml_clear_errors();

        try {
            // Parse XML with external entities disabled
            $dom = new \DOMDocument;
            $dom->resolveExternals = false;
            $dom->substituteEntities = false;
            $dom->recover = false;

            $result = $dom->loadXML($content, LIBXML_PARSEHUGE | LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NOCDATA);

            // Check for XML parsing errors
            $errors = libxml_get_errors();
            if (! empty($errors)) {
                return false;
            }

            return $result !== false;
        } catch (\Exception $e) {
            return false;
        } finally {
            // Restore original settings
            libxml_use_internal_errors($originalInternalErrors);
            libxml_clear_errors();
        }
    }

    /**
     * Generates metadata for an SVG attachment.
     *
     * @param  array  $metadata  The attachment metadata.
     * @param  int  $attachmentId  The attachment ID.
     * @return array The updated metadata.
     */
    public function generateSvgMetadata(array $metadata, int $attachmentId): array
    {
        $attachment = get_post($attachmentId);
        if (! $attachment || ! str_ends_with($attachment->post_mime_type, 'svg+xml')) {
            return $metadata;
        }

        $filePath = get_attached_file($attachmentId);
        if (! $filePath || ! file_exists($filePath)) {
            return $metadata;
        }

        $dimensions = $this->getSvgDimensions($filePath);
        if ($dimensions) {
            $metadata['width'] = $dimensions['width'];
            $metadata['height'] = $dimensions['height'];
        }

        return $metadata;
    }

    /**
     * Gets the dimensions of an SVG file using DOMDocument for robust parsing.
     *
     * @param  string  $filePath  The file path.
     * @return array|null The dimensions of the file, or null if not found.
     */
    private function getSvgDimensions(string $filePath): ?array
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        // Use DOMDocument for robust XML parsing instead of regex
        $originalInternalErrors = libxml_use_internal_errors(true);
        libxml_clear_errors();

        try {
            $dom = new \DOMDocument;
            $dom->resolveExternals = false;
            $dom->substituteEntities = false;

            if (! $dom->loadXML($content, LIBXML_PARSEHUGE | LIBXML_NOERROR | LIBXML_NOWARNING)) {
                return null;
            }

            $svgElement = $dom->documentElement;
            if (! $svgElement || $svgElement->nodeName !== 'svg') {
                return null;
            }

            // Try to get width and height attributes first
            $width = $svgElement->getAttribute('width');
            $height = $svgElement->getAttribute('height');

            if ($width && $height) {
                // Remove units (px, em, etc.) and convert to integer
                $width = (int) preg_replace('/[^0-9.]/', '', $width);
                $height = (int) preg_replace('/[^0-9.]/', '', $height);

                if ($width > 0 && $height > 0) {
                    return ['width' => $width, 'height' => $height];
                }
            }

            // Fallback to viewBox if width/height not available
            $viewBox = $svgElement->getAttribute('viewBox');
            if ($viewBox) {
                $viewBoxValues = preg_split('/[\s,]+/', trim($viewBox));
                if (count($viewBoxValues) >= 4) {
                    $width = (int) $viewBoxValues[2];
                    $height = (int) $viewBoxValues[3];

                    if ($width > 0 && $height > 0) {
                        return ['width' => $width, 'height' => $height];
                    }
                }
            }

            return null;
        } catch (\Exception $e) {
            return null;
        } finally {
            libxml_use_internal_errors($originalInternalErrors);
            libxml_clear_errors();
        }
    }

    /**
     * Adds SVG to the list of image size extensions.
     *
     * @param  array  $mimes  The list of image size extensions.
     * @return array The updated list of image size extensions.
     */
    public function addSvgToImageSizeExts(array $mimes): array
    {
        $mimes['image/svg+xml'] = 'svg';

        return $mimes;
    }

    /**
     * Allows SVG image mime types.
     *
     * @param  bool  $result  The result of the mime type check.
     * @param  string  $file  The file path.
     * @param  string  $filename  The file name.
     * @param  array  $mimes  The list of allowed mime types.
     * @return bool True if the mime type is allowed, false otherwise.
     */
    public function allowSvgImageMime(bool $result, string $file, string $filename, array $mimes): bool
    {
        return str_ends_with($filename, '.svg') || $result;
    }

    /**
     * Disables SVG srcset.
     *
     * @param  array  $imageMeta  The image metadata.
     * @param  array  $sizeArray  The size array.
     * @param  string  $imageSrc  The image source.
     * @param  int  $attachmentId  The attachment ID.
     * @return array The updated image metadata.
     */
    public function disableSvgSrcset(array $imageMeta, array $sizeArray, string $imageSrc, int $attachmentId): array
    {
        if (get_post_mime_type($attachmentId) === 'image/svg+xml' && is_array($imageMeta)) {
            $imageMeta['sizes'] = [];
        }

        return $imageMeta;
    }

    /**
     * Validates an existing attachment to ensure it is a safe SVG.
     *
     * @param  int  $attachmentId  The attachment ID.
     */
    public function validateExistingAttachment(int $attachmentId): void
    {
        $attachment = get_post($attachmentId);
        if (! $attachment || ! str_ends_with($attachment->post_mime_type, 'svg+xml')) {
            return;
        }

        $filePath = get_attached_file($attachmentId);
        if (! $filePath || ! file_exists($filePath)) {
            return;
        }

        $content = file_get_contents($filePath);
        if ($content !== false && ! $this->isValidSvg($content)) {
            unlink($filePath);
            wp_delete_attachment($attachmentId, true);

            wp_die('SVG file contains dangerous content and was rejected for security reasons.');
        }
    }
}

(new SvgUploadHandler)->init();
