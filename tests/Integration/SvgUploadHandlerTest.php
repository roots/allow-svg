<?php

declare(strict_types=1);

namespace AllowSvg\Tests\Integration;

use AllowSvg\SvgUploadHandler;
use AllowSvg\Tests\Support\TestStreamWrapper;
use PHPUnit\Framework\Attributes\DataProvider;
use Yoast\PHPUnitPolyfills\TestCases\TestCase as PolyfillTestCase;

final class SvgUploadHandlerTest extends PolyfillTestCase
{
    private SvgUploadHandler $handler;

    private string $fixturesPath;

    protected function set_up(): void
    {
        $this->handler = new SvgUploadHandler;
        $this->fixturesPath = __DIR__.'/../Fixtures/';
    }

    public function test_add_svg_mime_type_adds_svg_to_mimes(): void
    {
        $mimes = ['jpg' => 'image/jpeg'];

        $result = $this->handler->addSvgMimeType($mimes);

        $this->assertArrayHasKey('svg', $result);
        $this->assertEquals('image/svg+xml', $result['svg']);
        $this->assertArrayHasKey('jpg', $result); // Preserves existing
    }

    public function test_check_svg_filetype_correctly_identifies_svg_files(): void
    {
        $data = ['ext' => '', 'type' => ''];
        $filename = 'test.svg';
        $mimes = ['svg' => 'image/svg+xml'];

        $result = $this->handler->checkSvgFiletype($data, '/tmp/file', $filename, $mimes);

        $this->assertEquals('svg', $result['ext']);
        $this->assertEquals('image/svg+xml', $result['type']);
        $this->assertEquals('test.svg', $result['proper_filename']);
    }

    public function test_check_svg_filetype_ignores_non_svg_files(): void
    {
        $data = ['ext' => 'jpg', 'type' => 'image/jpeg'];
        $filename = 'test.jpg';
        $mimes = ['jpg' => 'image/jpeg'];

        $result = $this->handler->checkSvgFiletype($data, '/tmp/file', $filename, $mimes);

        $this->assertEquals('jpg', $result['ext']);
        $this->assertEquals('image/jpeg', $result['type']);
    }

    public function test_check_svg_filetype_handles_null_mimes(): void
    {
        $data = ['ext' => '', 'type' => ''];
        $filename = 'test.svg';

        $result = $this->handler->checkSvgFiletype($data, '/tmp/file', $filename, null);

        $this->assertEquals('svg', $result['ext']);
        $this->assertEquals('image/svg+xml', $result['type']);
    }

    public function test_handle_svg_upload_processes_valid_svg_file(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $validSvg = file_get_contents($this->fixturesPath.'valid.svg');
        file_put_contents($testFile, $validSvg);

        $file = [
            'name' => 'test.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => strlen($validSvg),
        ];

        $result = $this->handler->handleSvgUpload($file);

        // Should not change the original error code (0 = no error)
        $this->assertEquals(0, $result['error']);
        $this->assertEquals('test.svg', $result['name']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_rejects_malicious_content(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $maliciousSvg = file_get_contents($this->fixturesPath.'malicious-script.svg');
        file_put_contents($testFile, $maliciousSvg);

        $file = [
            'name' => 'malicious.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => strlen($maliciousSvg),
        ];

        $result = $this->handler->handleSvgUpload($file);

        // Should reject the file with an error
        $this->assertIsString($result['error']);
        $this->assertStringContainsString('dangerous content', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_rejects_invalid_svg_content(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $invalidContent = file_get_contents($this->fixturesPath.'not-svg.svg');
        file_put_contents($testFile, $invalidContent);

        $file = [
            'name' => 'fake.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => strlen($invalidContent),
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertIsString($result['error']);
        $this->assertStringContainsString('not a valid SVG', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_ignores_non_svg_files(): void
    {
        $file = [
            'name' => 'test.jpg',
            'type' => 'image/jpeg',
            'tmp_name' => '/tmp/test.jpg',
            'error' => 0,
            'size' => 1024,
        ];

        $result = $this->handler->handleSvgUpload($file);

        // Should return unchanged
        $this->assertEquals($file, $result);
    }

    public function test_handle_svg_upload_rejects_data_url_attacks(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $maliciousSvg = file_get_contents($this->fixturesPath.'malicious-data-url.svg');
        file_put_contents($testFile, $maliciousSvg);

        $file = [
            'name' => 'data-url-attack.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => strlen($maliciousSvg),
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertIsString($result['error']);
        $this->assertStringContainsString('dangerous content', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_rejects_css_expression_attacks(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $maliciousSvg = file_get_contents($this->fixturesPath.'malicious-css-expression.svg');
        file_put_contents($testFile, $maliciousSvg);

        $file = [
            'name' => 'css-expression-attack.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => strlen($maliciousSvg),
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertIsString($result['error']);
        $this->assertStringContainsString('dangerous content', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_rejects_foreign_object_attacks(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $maliciousSvg = file_get_contents($this->fixturesPath.'malicious-foreign-object.svg');
        file_put_contents($testFile, $maliciousSvg);

        $file = [
            'name' => 'foreign-object-attack.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => strlen($maliciousSvg),
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertIsString($result['error']);
        $this->assertStringContainsString('dangerous content', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_rejects_oversized_files(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $validSvg = file_get_contents($this->fixturesPath.'valid.svg');
        file_put_contents($testFile, $validSvg.str_repeat(' ', 6 * 1024 * 1024)); // Over 6MB, exceeding the 5MB limit

        $file = [
            'name' => 'large.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => 1024, // The browser's reported size, which isn't trusted
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertIsString($result['error']);
        $this->assertStringContainsString('exceeds maximum size limit', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_accepts_properly_sized_files(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $validSvg = file_get_contents($this->fixturesPath.'valid.svg');
        file_put_contents($testFile, $validSvg);

        $file = [
            'name' => 'normal.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => 1024, // 1KB - well under 5MB limit
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertEquals(0, $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_rejects_invalid_file_extensions(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $validSvg = file_get_contents($this->fixturesPath.'valid.svg');
        file_put_contents($testFile, $validSvg);

        $file = [
            'name' => 'test.txt', // Wrong extension
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => 1024,
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertIsString($result['error']);
        $this->assertStringContainsString('Invalid file type', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_accepts_valid_svg_extension(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $validSvg = file_get_contents($this->fixturesPath.'valid.svg');
        file_put_contents($testFile, $validSvg);

        $file = [
            'name' => 'test.svg', // Correct extension
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => 1024,
        ];

        $result = $this->handler->handleSvgUpload($file);

        $this->assertEquals(0, $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_handles_missing_filename(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        $validSvg = file_get_contents($this->fixturesPath.'valid.svg');
        file_put_contents($testFile, $validSvg);

        $file = [
            // Missing 'name' key
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => 1024,
        ];

        $result = $this->handler->handleSvgUpload($file);

        // Should still process since filename validation is skipped when name is missing
        $this->assertEquals(0, $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_result_accepts_valid_svg_in_stream_storage(): void
    {
        TestStreamWrapper::register();
        $url = TestStreamWrapper::url('valid.svg');
        file_put_contents($url, file_get_contents($this->fixturesPath.'valid.svg'));

        $upload = [
            'file' => $url,
            'url' => 'https://example.com/uploads/valid.svg',
            'type' => 'image/svg+xml',
        ];

        $result = $this->handler->handleSvgUploadResult($upload);

        $this->assertSame($upload, $result);
        $this->assertFileExists($url);

        unlink($url);
        TestStreamWrapper::unregister();
    }

    public function test_handle_svg_upload_result_rejects_malicious_svg_in_stream_storage(): void
    {
        TestStreamWrapper::register();
        $url = TestStreamWrapper::url('malicious.svg');
        file_put_contents($url, file_get_contents($this->fixturesPath.'malicious-script.svg'));

        $result = $this->handler->handleSvgUploadResult([
            'file' => $url,
            'url' => 'https://example.com/uploads/malicious.svg',
            'type' => 'image/svg+xml',
        ]);

        $this->assertArrayHasKey('error', $result);
        $this->assertStringContainsString('dangerous content', $result['error']);
        $this->assertFileDoesNotExist($url);

        TestStreamWrapper::unregister();
    }

    public function test_handle_svg_upload_result_rejects_missing_local_file(): void
    {
        $result = $this->handler->handleSvgUploadResult([
            'file' => sys_get_temp_dir().'/allow-svg-missing.svg',
            'url' => 'https://example.com/uploads/allow-svg-missing.svg',
            'type' => 'image/svg+xml',
        ]);

        $this->assertSame(['error' => 'Invalid file path.'], $result);
    }

    public function test_handle_svg_upload_checks_svg_sent_under_another_type(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        file_put_contents($testFile, file_get_contents($this->fixturesPath.'malicious-script.svg'));

        // The browser chooses the type, so it can't be what decides whether an .svg is checked
        $result = $this->handler->handleSvgUpload([
            'name' => 'image.svg',
            'type' => 'application/octet-stream',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => filesize($testFile),
        ]);

        $this->assertIsString($result['error']);
        $this->assertStringContainsString('dangerous content', $result['error']);

        unlink($testFile);
    }

    public function test_handle_svg_upload_result_rejects_oversized_files(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        file_put_contents($testFile, file_get_contents($this->fixturesPath.'valid.svg').str_repeat(' ', 6 * 1024 * 1024));

        $result = $this->handler->handleSvgUploadResult([
            'file' => $testFile,
            'url' => 'https://example.com/uploads/large.svg',
            'type' => 'image/svg+xml',
        ]);

        $this->assertSame(['error' => 'SVG file exceeds maximum size limit of 5MB.'], $result);
        $this->assertFileDoesNotExist($testFile);
    }

    public function test_check_svg_filetype_ignores_extension_case(): void
    {
        $result = $this->handler->checkSvgFiletype(['ext' => false, 'type' => false, 'proper_filename' => false], '/tmp/file', 'ICON.SVG', null);

        $this->assertEquals('svg', $result['ext']);
        $this->assertEquals('image/svg+xml', $result['type']);
    }

    public function test_handle_svg_upload_checks_by_the_last_extension(): void
    {
        $testFile = tempnam(sys_get_temp_dir(), 'svg_test_');
        file_put_contents($testFile, file_get_contents($this->fixturesPath.'malicious-script.svg'));
        $upload = fn (string $name) => ['name' => $name, 'type' => 'image/png', 'tmp_name' => $testFile, 'error' => 0, 'size' => filesize($testFile)];

        // Stored as .svg, so it's checked whatever the browser says it is
        $this->assertStringContainsString('dangerous content', (string) $this->handler->handleSvgUpload($upload('image.png.svg'))['error']);

        // Stored and served as .png, so it's not an SVG upload
        $this->assertSame($upload('image.svg.png'), $this->handler->handleSvgUpload($upload('image.svg.png')));

        unlink($testFile);
    }

    public function test_handle_svg_upload_result_rejects_unreadable_files_in_stream_storage(): void
    {
        TestStreamWrapper::register();
        $url = TestStreamWrapper::url('unreadable.svg');
        file_put_contents($url, file_get_contents($this->fixturesPath.'valid.svg'));

        $result = $this->handler->handleSvgUploadResult([
            'file' => $url,
            'url' => 'https://example.com/uploads/unreadable.svg',
            'type' => 'image/svg+xml',
        ]);

        $this->assertSame(['error' => 'SVG file could not be read to check it, so it was rejected.'], $result);
        $this->assertFileDoesNotExist($url);

        TestStreamWrapper::unregister();
    }

    public function test_handle_svg_upload_result_rejects_oversized_files_in_stream_storage(): void
    {
        TestStreamWrapper::register();
        $url = TestStreamWrapper::url('large.svg');
        file_put_contents($url, file_get_contents($this->fixturesPath.'valid.svg').str_repeat(' ', 6 * 1024 * 1024));

        $result = $this->handler->handleSvgUploadResult([
            'file' => $url,
            'url' => 'https://example.com/uploads/large.svg',
            'type' => 'image/svg+xml',
        ]);

        $this->assertSame(['error' => 'SVG file exceeds maximum size limit of 5MB.'], $result);
        $this->assertFileDoesNotExist($url);

        TestStreamWrapper::unregister();
    }

    public function test_validate_existing_attachment_accepts_a_safe_file(): void
    {
        $path = $this->attachedFile(file_get_contents($this->fixturesPath.'valid.svg'));

        $this->handler->validateExistingAttachment(1);

        $this->assertFileExists($path);
        $this->assertSame([], $GLOBALS['allow_svg_test_deleted_attachments'] ?? []);

        unlink($path);
    }

    public static function rejectedAttachmentProvider(): array
    {
        return [
            'unsafe' => ['malicious-script.svg', '', 'SVG file contains dangerous content and was rejected for security reasons.'],
            'too large' => ['valid.svg', str_repeat(' ', 6 * 1024 * 1024), 'SVG file exceeds maximum size limit of 5MB.'],
        ];
    }

    #[DataProvider('rejectedAttachmentProvider')]
    public function test_validate_existing_attachment_rejects_and_deletes(string $fixture, string $padding, string $message): void
    {
        $path = $this->attachedFile(file_get_contents($this->fixturesPath.$fixture).$padding);

        try {
            $this->handler->validateExistingAttachment(7);
            $this->fail('The attachment was accepted.');
        } catch (\RuntimeException $e) {
            $this->assertSame($message, $e->getMessage());
        }

        $this->assertFileDoesNotExist($path);
        $this->assertSame([7], $GLOBALS['allow_svg_test_deleted_attachments']);
    }

    public function test_validate_existing_attachment_rejects_unreadable_files(): void
    {
        TestStreamWrapper::register();
        $url = TestStreamWrapper::url('unreadable-attachment.svg');
        file_put_contents($url, file_get_contents($this->fixturesPath.'valid.svg'));
        $GLOBALS['allow_svg_test_attached_file'] = $url;
        $GLOBALS['allow_svg_test_deleted_attachments'] = [];

        try {
            $this->handler->validateExistingAttachment(9);
            $this->fail('The attachment was accepted.');
        } catch (\RuntimeException $e) {
            $this->assertSame('SVG file could not be read to check it, so it was rejected.', $e->getMessage());
        }

        $this->assertSame([9], $GLOBALS['allow_svg_test_deleted_attachments']);
        $this->assertFileDoesNotExist($url);

        TestStreamWrapper::unregister();
    }

    public function test_validate_existing_attachment_retries_a_failed_read(): void
    {
        TestStreamWrapper::register();
        $url = TestStreamWrapper::url('flaky-attachment.svg');
        file_put_contents($url, file_get_contents($this->fixturesPath.'valid.svg'));
        $GLOBALS['allow_svg_test_attached_file'] = $url;
        $GLOBALS['allow_svg_test_deleted_attachments'] = [];

        // The first read fails and the second succeeds, so the file is checked and kept
        $this->handler->validateExistingAttachment(3);

        $this->assertFileExists($url);
        $this->assertSame([], $GLOBALS['allow_svg_test_deleted_attachments']);

        unlink($url);
        TestStreamWrapper::unregister();
    }

    public function test_rejections_are_logged_with_their_reason(): void
    {
        $log = tempnam(sys_get_temp_dir(), 'svg_log_');
        $previousLog = ini_set('error_log', $log);
        $large = tempnam(sys_get_temp_dir(), 'svg_test_');
        file_put_contents($large, file_get_contents($this->fixturesPath.'valid.svg').str_repeat(' ', 6 * 1024 * 1024));
        TestStreamWrapper::register();
        $unreadable = TestStreamWrapper::url('unreadable-logged.svg');
        file_put_contents($unreadable, file_get_contents($this->fixturesPath.'valid.svg'));

        try {
            $this->handler->handleSvgUpload(['name' => 'large.svg', 'type' => 'image/svg+xml', 'tmp_name' => $large, 'error' => 0, 'size' => 1024]);
            $this->handler->handleSvgUploadResult(['file' => sys_get_temp_dir().'/allow-svg-moved.svg', 'url' => 'https://example.com/uploads/moved.svg', 'type' => 'image/svg+xml']);
            $this->handler->handleSvgUploadResult(['file' => $unreadable, 'url' => 'https://example.com/uploads/unreadable-logged.svg', 'type' => 'image/svg+xml']);
        } finally {
            ini_set('error_log', $previousLog);
            TestStreamWrapper::unregister();
            unlink($large);
        }

        $logged = file_get_contents($log);
        unlink($log);

        $this->assertStringContainsString('SVG upload attempt: large.svg (size: over the size limit)', $logged);
        $this->assertStringContainsString('SVG file exceeds maximum size limit of 5MB. (large.svg)', $logged);
        $this->assertStringContainsString('Invalid file path. ('.sys_get_temp_dir().'/allow-svg-moved.svg)', $logged);
        $this->assertStringContainsString('SVG file could not be read to check it, so it was rejected. ('.$unreadable.')', $logged);
    }

    public function test_upload_result_check_runs_after_other_upload_filters(): void
    {
        $priorities = array_column(array_filter(
            $GLOBALS['allow_svg_test_filters']['wp_handle_upload'] ?? [],
            fn (array $filter) => is_array($filter['callback']) && $filter['callback'][1] === 'handleSvgUploadResult',
        ), 'priority');

        $this->assertSame([PHP_INT_MAX], $priorities);
    }

    public function test_validate_existing_attachment_skips_files_checked_on_upload(): void
    {
        $path = $this->attachedFile(file_get_contents($this->fixturesPath.'valid.svg'));

        $this->handler->handleSvgUploadResult(['file' => $path, 'url' => 'https://example.com/uploads/checked.svg', 'type' => 'image/svg+xml']);

        // Not read again for the attachment the check was for
        file_put_contents($path, file_get_contents($this->fixturesPath.'malicious-script.svg'));
        $this->handler->validateExistingAttachment(1);

        $this->assertFileExists($path);

        // A second attachment for the same file is checked again
        try {
            $this->handler->validateExistingAttachment(2);
            $this->fail('The changed file was accepted.');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('dangerous content', $e->getMessage());
        }

        $this->assertFileDoesNotExist($path);
    }

    protected function tear_down(): void
    {
        unset($GLOBALS['allow_svg_test_attached_file'], $GLOBALS['allow_svg_test_deleted_attachments']);
    }

    /**
     * Writes a file for get_attached_file() to return.
     */
    private function attachedFile(string $content): string
    {
        $path = tempnam(sys_get_temp_dir(), 'svg_attachment_');
        file_put_contents($path, $content);
        $GLOBALS['allow_svg_test_attached_file'] = $path;
        $GLOBALS['allow_svg_test_deleted_attachments'] = [];

        return $path;
    }
}
