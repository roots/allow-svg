<?php

declare(strict_types=1);

require_once __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/../allow-svg.php';

// WordPress test environment constants
define('WP_CONTENT_DIR', '/tmp/wp-content');
define('ABSPATH', '/tmp/wordpress/');

// Mock WordPress functions for unit tests
if (! function_exists('wp_check_filetype')) {
    function wp_check_filetype(string $filename, ?array $mimes = null): array
    {
        $ext = pathinfo($filename, PATHINFO_EXTENSION);

        return [
            'ext' => $ext,
            'type' => $mimes[$ext] ?? false,
        ];
    }
}

if (! function_exists('get_allowed_mime_types')) {
    function get_allowed_mime_types(): array
    {
        return [
            'svg' => 'image/svg+xml',
            'jpg|jpeg|jpe' => 'image/jpeg',
            'png' => 'image/png',
        ];
    }
}

if (! function_exists('get_post')) {
    function get_post(int $attachmentId): ?\stdClass
    {
        $post = new \stdClass;
        $post->post_mime_type = 'image/svg+xml';

        return $post;
    }
}

if (! function_exists('get_attached_file')) {
    function get_attached_file(int $attachmentId): string
    {
        return '/tmp/test.svg';
    }
}

if (! function_exists('get_post_mime_type')) {
    function get_post_mime_type(int $attachmentId): string
    {
        return 'image/svg+xml';
    }
}

if (! function_exists('error_log')) {
    function error_log(string $message): bool
    {
        return true;
    }
}
