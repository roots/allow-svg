<?php

declare(strict_types=1);

namespace AllowSvg\Tests\Unit;

use AllowSvg\SvgUploadHandler;
use Yoast\PHPUnitPolyfills\TestCases\TestCase as PolyfillTestCase;

final class SvgSecurityValidatorTest extends PolyfillTestCase
{
    private SvgUploadHandler $handler;

    private string $fixturesPath;

    protected function set_up(): void
    {
        $this->handler = new SvgUploadHandler;
        $this->fixturesPath = __DIR__.'/../Fixtures/';
    }

    public function test_is_valid_svg_returns_true_for_valid_svg(): void
    {
        $validSvg = file_get_contents($this->fixturesPath.'valid.svg');

        $result = $this->handler->isValidSvg($validSvg);

        $this->assertTrue($result);
    }

    public function test_is_valid_svg_returns_false_for_empty_content(): void
    {
        $result = $this->handler->isValidSvg('');

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_returns_false_for_non_svg_content(): void
    {
        $nonSvg = file_get_contents($this->fixturesPath.'not-svg.svg');

        $result = $this->handler->isValidSvg($nonSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_svg_with_script_tags(): void
    {
        $maliciousSvg = file_get_contents($this->fixturesPath.'malicious-script.svg');

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result); // Should reject malicious content
    }

    public function test_is_valid_svg_rejects_svg_with_javascript_urls(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><text>Click me</text></a></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_svg_with_event_handlers(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><circle cx="50" cy="50" r="40"/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_svg_with_external_references(): void
    {
        $maliciousSvg = file_get_contents($this->fixturesPath.'malicious-external.svg');

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_iframe_tags(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><iframe src="http://evil.com"></iframe></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_object_tags(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><object data="http://evil.com"></object></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_embed_tags(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><embed src="http://evil.com"></embed></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_style_tags(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><style>body { background: url("javascript:alert(1)"); }</style></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_accepts_safe_svg(): void
    {
        $safeSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="40" fill="blue"/><rect x="10" y="10" width="20" height="20" fill="red"/></svg>';

        $result = $this->handler->isValidSvg($safeSvg);

        $this->assertTrue($result);
    }

    public function test_is_valid_svg_rejects_missing_svg_tags(): void
    {
        $notSvg = '<div>This is not an SVG</div>';

        $result = $this->handler->isValidSvg($notSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_data_urls_with_scripts(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/svg+xml;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_data_urls_with_html(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><image href="data:text/html,<script>alert(1)</script>"/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_css_url_with_javascript(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><rect style="background: url(javascript:alert(1))"/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_inline_style_expressions(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><rect style="background: expression(alert(1))"/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_inline_style_javascript_urls(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><rect style="background: javascript:alert(1)"/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_foreign_object_with_html(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><html><script>alert(1)</script></html></foreignObject></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_nested_script_tags(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg"><defs><script>alert(1)</script></defs><circle cx="50" cy="50" r="40"/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_event_handlers_with_word_boundaries(): void
    {
        $maliciousSvg = '<svg xmlns="http://www.w3.org/2000/svg" data-onclick="alert(1)"><circle cx="50" cy="50" r="40"/></svg>';

        $result = $this->handler->isValidSvg($maliciousSvg);

        // Should NOT reject data-onclick (false positive prevention)
        $this->assertTrue($result);

        // But should reject actual event handlers
        $actualMalicious = '<svg xmlns="http://www.w3.org/2000/svg" onclick="alert(1)"><circle cx="50" cy="50" r="40"/></svg>';
        $result2 = $this->handler->isValidSvg($actualMalicious);
        $this->assertFalse($result2);
    }

    public function test_is_valid_svg_rejects_doctype_declarations(): void
    {
        $xxeSvg = '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>';

        $result = $this->handler->isValidSvg($xxeSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_entity_declarations(): void
    {
        $entityBombSvg = '<!DOCTYPE svg [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><svg xmlns="http://www.w3.org/2000/svg">&lol2;</svg>';

        $result = $this->handler->isValidSvg($entityBombSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_entity_references(): void
    {
        $entityRefSvg = '<svg xmlns="http://www.w3.org/2000/svg">&lt;script&gt;alert(1)&lt;/script&gt;</svg>';

        $result = $this->handler->isValidSvg($entityRefSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_xxe_file_inclusion(): void
    {
        $xxeFileSvg = '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>';

        $result = $this->handler->isValidSvg($xxeFileSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_xxe_http_requests(): void
    {
        $xxeHttpSvg = '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://evil.com/payload">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>';

        $result = $this->handler->isValidSvg($xxeHttpSvg);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_nested_entity_bomb(): void
    {
        $nestedEntityBomb = '<!DOCTYPE svg [
            <!ENTITY lol "lol">
            <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
            <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        ]><svg xmlns="http://www.w3.org/2000/svg">&lol3;</svg>';

        $result = $this->handler->isValidSvg($nestedEntityBomb);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_namespaced_script_tags(): void
    {
        $namespacedScript = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:svg="http://www.w3.org/2000/svg">
            <svg:script>alert(1)</svg:script>
        </svg>';

        $result = $this->handler->isValidSvg($namespacedScript);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_namespaced_foreign_objects(): void
    {
        $namespacedForeignObject = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:html="http://www.w3.org/1999/xhtml">
            <html:foreignobject><html:script>alert(1)</html:script></html:foreignobject>
        </svg>';

        $result = $this->handler->isValidSvg($namespacedForeignObject);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_entity_encoded_javascript(): void
    {
        $entityEncodedJs = '<svg xmlns="http://www.w3.org/2000/svg">
            <a href="j&#x61;v&#x61;s&#x63;r&#x69;p&#x74;:alert(1)">Click</a>
        </svg>';

        $result = $this->handler->isValidSvg($entityEncodedJs);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_obfuscated_event_handlers(): void
    {
        $obfuscatedHandler = '<svg xmlns="http://www.w3.org/2000/svg">
            <rect &amp;onclick="alert(1)" width="100" height="100"/>
        </svg>';

        $result = $this->handler->isValidSvg($obfuscatedHandler);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_cdata_with_scripts(): void
    {
        $cdataScript = '<svg xmlns="http://www.w3.org/2000/svg">
            <![CDATA[<script>alert(1)</script>]]>
        </svg>';

        $result = $this->handler->isValidSvg($cdataScript);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_unicode_escapes(): void
    {
        $unicodeEscape = '<svg xmlns="http://www.w3.org/2000/svg">
            <a href="\\u006a\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074:alert(1)">Click</a>
        </svg>';

        $result = $this->handler->isValidSvg($unicodeEscape);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_hex_escapes(): void
    {
        $hexEscape = '<svg xmlns="http://www.w3.org/2000/svg">
            <a href="\\x6a\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74:alert(1)">Click</a>
        </svg>';

        $result = $this->handler->isValidSvg($hexEscape);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_dangerous_functions(): void
    {
        $evalCall = '<svg xmlns="http://www.w3.org/2000/svg">
            <text onclick="eval(atob(\'YWxlcnQoMSk=\'))">Click</text>
        </svg>';

        $result = $this->handler->isValidSvg($evalCall);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_spaced_javascript(): void
    {
        $spacedJs = '<svg xmlns="http://www.w3.org/2000/svg">
            <a href="j a v a s c r i p t : alert(1)">Click</a>
        </svg>';

        $result = $this->handler->isValidSvg($spacedJs);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_entity_encoded_scripts_after_decoding(): void
    {
        $entityEncodedScript = '<svg xmlns="http://www.w3.org/2000/svg">
            &lt;script&gt;alert(1)&lt;/script&gt;
        </svg>';

        $result = $this->handler->isValidSvg($entityEncodedScript);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_numeric_entity_encoded_javascript(): void
    {
        $numericEntityJs = '<svg xmlns="http://www.w3.org/2000/svg">
            <a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">Click</a>
        </svg>';

        $result = $this->handler->isValidSvg($numericEntityJs);

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_rejects_mixed_case_event_handlers(): void
    {
        $mixedCaseHandler = '<svg xmlns="http://www.w3.org/2000/svg">
            <rect onClick="alert(1)" width="100" height="100"/>
        </svg>';

        $result = $this->handler->isValidSvg($mixedCaseHandler);

        $this->assertFalse($result);
    }
}
