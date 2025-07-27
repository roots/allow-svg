<?php

declare(strict_types=1);

namespace AllowSvg\Tests\Integration;

use AllowSvg\SvgUploadHandler;
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

    public function test_allow_svg_image_mime_returns_true_for_svg_files(): void
    {
        $result = $this->handler->allowSvgImageMime(false, '/tmp/test', 'test.svg', []);

        $this->assertTrue($result);
    }

    public function test_allow_svg_image_mime_preserves_original_for_non_svg(): void
    {
        $result = $this->handler->allowSvgImageMime(false, '/tmp/test', 'test.jpg', []);

        $this->assertFalse($result);

        $result = $this->handler->allowSvgImageMime(true, '/tmp/test', 'test.jpg', []);

        $this->assertTrue($result);
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
        file_put_contents($testFile, $validSvg);

        $file = [
            'name' => 'large.svg',
            'type' => 'image/svg+xml',
            'tmp_name' => $testFile,
            'error' => 0,
            'size' => 6 * 1024 * 1024, // 6MB - exceeds 5MB limit
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
}
