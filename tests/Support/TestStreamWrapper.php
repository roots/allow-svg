<?php

declare(strict_types=1);

namespace AllowSvg\Tests\Support;

/**
 * A minimal stream wrapper standing in for remote upload storage (such as
 * an s3:// wrapper): files live in a temporary directory, but PHP only sees
 * them through the wrapper, so realpath() can't resolve them.
 */
final class TestStreamWrapper
{
    public const SCHEME = 'allowsvgtest';

    /** @var resource|null */
    public $context;

    /** @var resource|null */
    private $handle;

    /** "flaky…" files whose first read has already failed. */
    private static array $failedOnce = [];

    public static function register(): void
    {
        if (! in_array(self::SCHEME, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::SCHEME, self::class);
        }

        if (! is_dir(self::root())) {
            mkdir(self::root(), 0777, true);
        }
    }

    public static function unregister(): void
    {
        if (in_array(self::SCHEME, stream_get_wrappers(), true)) {
            stream_wrapper_unregister(self::SCHEME);
        }

        self::$failedOnce = [];
    }

    public static function url(string $name): string
    {
        return self::SCHEME.'://'.$name;
    }

    private static function root(): string
    {
        return sys_get_temp_dir().'/allow-svg-stream';
    }

    private static function local(string $url): string
    {
        return self::root().'/'.substr($url, strlen(self::SCHEME.'://'));
    }

    public function stream_open(string $path, string $mode): bool
    {
        // Files named "unreadable…" exist but can't be opened for reading, like
        // a remote read that fails; "flaky…" files fail only the first read.
        if (str_starts_with($mode, 'r')) {
            if (str_starts_with(basename($path), 'unreadable')) {
                return false;
            }

            if (str_starts_with(basename($path), 'flaky') && ! isset(self::$failedOnce[$path])) {
                self::$failedOnce[$path] = true;

                return false;
            }
        }

        $this->handle = fopen(self::local($path), $mode) ?: null;

        return $this->handle !== null;
    }

    public function stream_read(int $count): string|false
    {
        return fread($this->handle, $count);
    }

    public function stream_write(string $data): int|false
    {
        return fwrite($this->handle, $data);
    }

    public function stream_eof(): bool
    {
        return feof($this->handle);
    }

    public function stream_stat(): array|false
    {
        return fstat($this->handle);
    }

    public function stream_close(): void
    {
        fclose($this->handle);
    }

    public function url_stat(string $path, int $flags): array|false
    {
        $local = self::local($path);

        return file_exists($local) ? stat($local) : false;
    }

    public function unlink(string $path): bool
    {
        return unlink(self::local($path));
    }
}
