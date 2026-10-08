<?php

declare(strict_types=1);

require_once __DIR__.'/../vendor/autoload.php';

// WordPress test environment constants. Defined before the plugin loads: it
// exits when ABSPATH isn't set, which ended the test run with a passing status.
define('WP_CONTENT_DIR', '/tmp/wp-content');
define('ABSPATH', '/tmp/wordpress/');

// The plugin registers its hooks as it loads.
if (! function_exists('add_filter')) {
    function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): bool
    {
        return true;
    }
}

if (! function_exists('add_action')) {
    function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): bool
    {
        return true;
    }
}

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

require_once __DIR__.'/../allow-svg.php';
