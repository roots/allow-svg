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
    /** Largest SVG accepted, in bytes, on every upload path. */
    private const MAX_FILE_SIZE = 5 * 1024 * 1024;

    private const TOO_LARGE_MESSAGE = 'SVG file exceeds maximum size limit of '.(self::MAX_FILE_SIZE / 1024 / 1024).'MB.';

    private const UNREADABLE_MESSAGE = 'SVG file could not be read to check it, so it was rejected.';

    private const NOT_SVG_MESSAGE = 'File is not a valid SVG.';

    private const UNSAFE_MESSAGE = 'SVG file contains dangerous content and was rejected for security reasons.';

    private readonly array $dangerousPatterns;

    /** Files handleSvgUploadResult() has checked in this request, by path. */
    private array $checkedFiles = [];

    /**
     * Initializes the plugin.
     */
    public function __construct()
    {
        $this->dangerousPatterns = [
            // Script tag patterns - including namespaced variants
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/<[\w:]+:script\b/i', // Namespaced script tags (e.g., svg:script)

            // JavaScript patterns
            '/javascript:/i',

            // Event handlers (comprehensive coverage)
            // Event handlers like onclick and onload: an attribute name that
            // starts with "on", so data-onclick and similar don't match.
            '/(?<![\w-])on[a-z]+\s*=/i',

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
            '/behavior\s*:/i', // IE CSS behaviors

            // Data URL threats
            '/data:\s*[^,]*(script|javascript)/i', // Data URLs with scripts/javascript
            '/data:\s*text\/html/i', // Data URLs with HTML content
            '/href\s*=\s*["\']?data:.*base64/i', // Block base64-encoded data in href

            // XML/DTD threats (XXE and entity bomb protection); DOCTYPE and
            // ENTITY declarations are found with a plain text search in
            // hasDeclaration(), which stays fast on large files without PCRE JIT.
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
        // Last, so it checks the file as stored after any other plugin changes it
        add_filter('wp_handle_upload', [$this, 'handleSvgUploadResult'], PHP_INT_MAX, 2);
        add_filter('wp_generate_attachment_metadata', [$this, 'generateSvgMetadata'], 10, 2);
        add_filter('getimagesize_mimes_to_exts', [$this, 'addSvgToImageSizeExts']);
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
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

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
        // The type comes from the browser, so a .svg sent under another type
        // is checked too.
        $ext = strtolower(pathinfo($file['name'] ?? '', PATHINFO_EXTENSION));
        $declaredSvg = ($file['type'] ?? '') === 'image/svg+xml';

        if (! $declaredSvg && $ext !== 'svg') {
            return $file;
        }

        // Validate file extension
        if (isset($file['name']) && $ext !== 'svg') {
            $file['error'] = 'Invalid file type. Only SVG files are allowed.';
            $this->logRejection($file['error'], $file['name']);

            return $file;
        }

        // Validate file path security
        $filePath = realpath($file['tmp_name']);
        if ($filePath === false || ! is_file($filePath)) {
            $file['error'] = 'Invalid file path.';
            $this->logRejection($file['error'], $file['name'] ?? $file['tmp_name']);

            return $file;
        }

        // Reads the file itself, so its actual size counts, not the size the
        // browser reported
        $content = $this->readFile($filePath);

        // Log upload attempt. The read stops just past the limit, so a larger
        // file's exact size isn't known.
        if ($content !== null && isset($file['name'])) {
            $size = strlen($content) > self::MAX_FILE_SIZE ? 'over the size limit' : strlen($content).' bytes';
            error_log(sprintf('SVG upload attempt: %s (size: %s)', $file['name'], $size));
        }

        $error = $this->rejectionMessage($content);
        if ($error !== null) {
            $this->logRejection($error, $file['name'] ?? $file['tmp_name']);
            $file['error'] = $error;
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

        // Validate file path security. Uploads kept in remote storage behind a
        // stream wrapper (e.g. s3://) have no real path; the file functions
        // below read them through the wrapper as they are.
        $filePath = wp_is_stream($upload['file']) ? $upload['file'] : realpath($upload['file']);
        if ($filePath === false || ! is_file($filePath)) {
            // Logged because another plugin moving the file would make every
            // SVG upload fail here
            $this->logRejection('Invalid file path.', $upload['file']);

            return [
                'error' => 'Invalid file path.',
            ];
        }

        // The file was just written in this request, so one that can't be read
        // can't be checked and is rejected
        $content = $this->readFile($filePath);
        $error = $this->rejectionMessage($content);

        if ($error !== null) {
            $this->logRejection($error, $upload['file']);

            // Delete the uploaded file
            unlink($filePath);

            return [
                'error' => $error,
            ];
        }

        // add_attachment doesn't need to read it again
        $this->checkedFiles[$upload['file']] = true;

        return $upload;
    }

    /**
     * Reads a file for checking, at most one byte past the size limit, so the
     * limit holds even when the file's size can't be determined.
     *
     * @param  string  $filePath  The file path.
     * @return string|null The content, or null if the file can't be read.
     */
    private function readFile(string $filePath): ?string
    {
        // Silenced: callers turn a failed read into a rejection with its own message
        $content = @file_get_contents($filePath, false, null, 0, self::MAX_FILE_SIZE + 1);

        return $content === false ? null : $content;
    }

    /**
     * The reason to reject a file's content, if any.
     *
     * @param  string|null  $content  The content from readFile().
     * @return string|null The error message, or null if the content is acceptable.
     */
    private function rejectionMessage(?string $content): ?string
    {
        return match (true) {
            $content === null => self::UNREADABLE_MESSAGE,
            strlen($content) > self::MAX_FILE_SIZE => self::TOO_LARGE_MESSAGE,
            ! str_contains($content, '<svg') || ! str_contains($content, '</svg>') => self::NOT_SVG_MESSAGE,
            ! $this->isValidSvg($content) => self::UNSAFE_MESSAGE,
            default => null,
        };
    }

    /**
     * Logs why a file was rejected, so failures like unreadable remote
     * storage show up as well as unsafe content.
     *
     * @param  string  $error  The rejection message.
     * @param  string  $file  The file name or path.
     */
    private function logRejection(string $error, string $file): void
    {
        error_log(sprintf('%s (%s)', $error, $file));
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

        if ($this->hasDeclaration($content)) {
            return false;
        }

        // Check for dangerous patterns. A pattern that can't be evaluated (it
        // returns false, e.g. at the backtrack limit) rejects the file too, so a
        // check never passes by failing.
        foreach ($this->dangerousPatterns as $pattern) {
            if (preg_match($pattern, $content) !== 0) {
                return false;
            }
        }

        // Additional checks for obfuscation and entity encoding
        $decodedContent = $this->decodeEntities($content);
        if ($decodedContent === null || $this->hasDeclaration($decodedContent)) {
            return false;
        }

        foreach ($this->dangerousPatterns as $pattern) {
            if (preg_match($pattern, $decodedContent) !== 0) {
                return false;
            }
        }

        if ($this->isUnsafeDocument($content)) {
            return false;
        }

        // Additional XML parsing with disabled external entities for XXE protection
        if (! $this->isValidXml($content)) {
            return false;
        }

        return true;
    }

    /**
     * Namespaces whose elements browsers render or run in an XML document:
     * XHTML and MathML, and XSLT, which a stylesheet instruction can apply.
     */
    private const RENDERED_NAMESPACES = [
        'http://www.w3.org/1999/xhtml',
        'http://www.w3.org/1998/Math/MathML',
        'http://www.w3.org/1999/XSL/Transform',
    ];

    /** Elements that run or embed content, rejected in any namespace. */
    private const DANGEROUS_ELEMENTS = ['script', 'iframe', 'object', 'embed', 'foreignobject'];

    /**
     * Checks the parsed document, where text, comments and value size can't
     * hide anything from a pattern. Rejects a doctype, processing instructions
     * other than XMP metadata (xpacket), a root that isn't an SVG element in the
     * SVG namespace, elements from rendered namespaces or that run or embed
     * content, event handler attributes (and animations that target them), and
     * script URLs split up to slip past the patterns: browsers drop tabs,
     * newlines and other control characters from URLs, so "java&#9;script:"
     * still runs. Attribute values have their character references resolved,
     * then are compared with all whitespace and control characters removed.
     *
     * @param  string  $content  The SVG content.
     * @return bool True if the document is unsafe, or doesn't parse.
     */
    private function isUnsafeDocument(string $content): bool
    {
        $originalInternalErrors = libxml_use_internal_errors(true);

        try {
            $dom = new \DOMDocument;
            $dom->resolveExternals = false;
            $dom->substituteEntities = false;

            if (! $dom->loadXML($content, LIBXML_NONET)) {
                return true;
            }

            if ($dom->doctype) {
                return true;
            }

            $root = $dom->documentElement;
            if (! $root || $root->localName !== 'svg' || $root->namespaceURI !== 'http://www.w3.org/2000/svg') {
                return true;
            }

            // Walk the document one node at a time, in document order, instead
            // of collecting every node up front, which takes memory in
            // proportion to the number of attributes.
            $node = $dom->firstChild;
            while ($node) {
                if ($this->isUnsafeNode($node)) {
                    return true;
                }

                if ($node->firstChild) {
                    $node = $node->firstChild;

                    continue;
                }

                while ($node && ! $node->nextSibling) {
                    $node = $node->parentNode;
                }

                $node = $node?->nextSibling;
            }

            return false;
        } finally {
            libxml_use_internal_errors($originalInternalErrors);
            libxml_clear_errors();
        }
    }

    /**
     * Checks for DOCTYPE and ENTITY declarations (XXE and entity expansion)
     * with a plain text search, which unlike a pattern stays fast on large
     * files when PCRE JIT is off.
     *
     * @param  string  $content  The content to check.
     * @return bool True if the content contains a declaration.
     */
    private function hasDeclaration(string $content): bool
    {
        return stripos($content, '<!DOCTYPE') !== false || stripos($content, '<!ENTITY') !== false;
    }

    /**
     * Checks one node of the parsed document, with its attributes.
     *
     * @param  \DOMNode  $node  The node.
     * @return bool True if the node is unsafe.
     */
    private function isUnsafeNode(\DOMNode $node): bool
    {
        // An xml-stylesheet instruction can apply XSLT to the document.
        if ($node instanceof \DOMProcessingInstruction) {
            return $node->target !== 'xpacket';
        }

        if (! $node instanceof \DOMElement) {
            return false;
        }

        if (in_array($node->namespaceURI, self::RENDERED_NAMESPACES, true)
            || in_array(strtolower($node->localName), self::DANGEROUS_ELEMENTS, true)) {
            return true;
        }

        foreach ($node->attributes as $attribute) {
            // Event handlers, whatever their namespace.
            if (str_starts_with(strtolower($attribute->localName), 'on')) {
                return true;
            }

            // Animations naming an event handler as their target.
            if ($attribute->localName === 'attributeName' && str_starts_with(strtolower(trim($attribute->value)), 'on')) {
                return true;
            }

            $compact = preg_replace('/[\x00-\x20\x7F]+/', '', $attribute->value);
            if ($compact === null) {
                return true;
            }

            $compact = strtolower($compact);
            foreach (['javascript:', 'vbscript:', 'data:text/html', 'data:image/svg+xml'] as $scheme) {
                if (str_contains($compact, $scheme)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Decodes HTML entities and numeric character references to reveal obfuscated content.
     *
     * @param  string  $content  The content to decode.
     * @return string|null The decoded content, or null if a pattern couldn't be evaluated.
     */
    private function decodeEntities(string $content): ?string
    {
        // Decode HTML entities
        $content = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Decode hexadecimal numeric character references
        $content = preg_replace_callback('/&#x([0-9a-f]+);/i', function ($matches) {
            $codepoint = hexdec($matches[1]);

            return $codepoint <= 0x10FFFF ? mb_chr($codepoint, 'UTF-8') : '';
        }, $content);

        if ($content === null) {
            return null;
        }

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

            $result = $dom->loadXML($content, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NOCDATA);

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

            if (! $dom->loadXML($content, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING)) {
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

        // Checked when it was uploaded in this request; each check covers one
        // attachment
        if (isset($this->checkedFiles[$filePath])) {
            unset($this->checkedFiles[$filePath]);

            return;
        }

        // A read can fail briefly on remote storage, so try twice before
        // rejecting a file that can't be checked
        $error = $this->rejectionMessage($this->readFile($filePath) ?? $this->readFile($filePath));
        if ($error === null) {
            return;
        }

        $this->logRejection($error, $filePath);
        unlink($filePath);
        wp_delete_attachment($attachmentId, true);

        wp_die($error);
    }
}

(new SvgUploadHandler)->init();
