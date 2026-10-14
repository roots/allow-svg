<?php

declare(strict_types=1);

namespace AllowSvg\Tests\Unit;

use AllowSvg\SvgUploadHandler;
use PHPUnit\Framework\Attributes\DataProvider;
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

    /**
     * Browsers drop tabs and newlines from URLs, so each of these runs as a
     * script URL. XML turns a literal tab or newline in an attribute into a
     * space, but HTML doesn't, which matters when an SVG is inlined into a page.
     */
    public static function splitScriptUrlProvider(): array
    {
        $link = fn (string $attributes, string $before = '') => '<svg xmlns="http://www.w3.org/2000/svg">'.$before.'<a '.$attributes.'><text>Click</text></a></svg>';

        return [
            'tab' => [$link("href=\"java\tscript:alert(1)\"")],
            'newline' => [$link("href=\"java\nscript:alert(1)\"")],
            'encoded tab' => [$link('href="java&#x09;script:alert(1)"')],
            'encoded newline' => [$link('href="java&#10;script:alert(1)"')],
            'encoded carriage return with leading zeros' => [$link('href="java&#x000D;script:alert(1)"')],
            'single-quoted value' => [$link("href='java&#9;script:alert(1)'")],
            'vbscript' => [$link('href="vb&#9;script:msgbox(1)"')],
            'data: HTML' => [$link('', '<a><set attributeName="href" to="data:text/h&#9;tml,%3Cscript%3Ealert(1)%3C/script%3E"/></a>')],
            'data: SVG' => [$link('', '<image href="data:image/svg+xml,%3Csvg%3E%3C/svg%3E"/>')],
            'data: SVG split by a tab' => [$link('', '<image href="data:image/s&#9;vg+xml,%3Csvg%3E%3C/svg%3E"/>')],
            'SMIL set' => [$link('', '<a><set attributeName="href" to="java&#9;script:alert(1)"/></a>')],
            'SMIL animate values' => [$link('', '<a><animate attributeName="href" values="#;java&#9;script:alert(1)"/></a>')],
            'after a quote in a comment' => [$link('href="java&#9;script:alert(1)"', '<!--="-->')],
            'after a quote in text' => [$link('href="java&#9;script:alert(1)"', '<text>x="</text>')],
            'after a quote in a processing instruction' => [$link('href="java&#9;script:alert(1)"', '<?x ="?>')],
            'after a quote in CDATA' => [$link('href="java&#9;script:alert(1)"', '<text><![CDATA[="]]></text>')],
            'after a value over 1MB' => [$link('href="java&#9;script:alert(1)"', '<path d="'.str_repeat('M0 0L1 1', 150000).'"/>')],
            'beside a value over 1MB' => [$link('href="java&#9;script:alert(1)" title="'.str_repeat('M0 0L1 1', 150000).'"')],
        ];
    }

    #[DataProvider('splitScriptUrlProvider')]
    public function test_is_valid_svg_rejects_split_script_urls(string $svg): void
    {
        $this->assertFalse($this->handler->isValidSvg($svg));
    }

    public function test_is_valid_svg_rejects_event_handlers_on_their_own_line(): void
    {
        foreach (["\n", "\t", "\r\n  "] as $separator) {
            $svg = '<svg xmlns="http://www.w3.org/2000/svg"'.$separator.'onload="alert(1)"><circle cx="50" cy="50" r="40"/></svg>';

            $this->assertFalse($this->handler->isValidSvg($svg));
        }
    }

    public function test_is_valid_svg_accepts_quotes_in_text_and_large_path_data(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><text>x="1" and y=\'2\'</text><path d="'.str_repeat('M0 0L1 1', 150000).'"/><a href="#top"><text>Top</text></a></svg>';

        $this->assertTrue($this->handler->isValidSvg($svg));
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

    public function test_is_valid_svg_rejects_when_a_pattern_cannot_be_evaluated(): void
    {
        // A pattern that errors instead of matching (here, one that doesn't
        // compile; in practice, one that hits the backtrack limit) must not let
        // a file through. The handler gets a pattern list of just that pattern.
        $handler = (new \ReflectionClass(SvgUploadHandler::class))->newInstanceWithoutConstructor();
        (function (): void {
            $this->dangerousPatterns = ['/(/'];
        })->call($handler);

        $result = @$handler->isValidSvg(file_get_contents($this->fixturesPath.'valid.svg'));

        $this->assertFalse($result);
    }

    public function test_is_valid_svg_accepts_attribute_names_containing_script(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><g description="A circle"><circle cx="50" cy="50" r="40"/></g></svg>';

        $this->assertTrue($this->handler->isValidSvg($svg));
    }

    public static function nonSvgRootProvider(): array
    {
        return [
            'another root element' => ['<doc><svg xmlns="http://www.w3.org/2000/svg"></svg></doc>'],
            'no SVG namespace' => ['<svg><rect width="1" height="1"/></svg>'],
            'another namespace' => ['<svg xmlns="http://www.w3.org/1999/xhtml"><rect width="1" height="1"/></svg>'],
        ];
    }

    #[DataProvider('nonSvgRootProvider')]
    public function test_is_valid_svg_rejects_documents_without_an_svg_root(string $svg): void
    {
        $this->assertFalse($this->handler->isValidSvg($svg));
    }

    public static function eventHandlerDocumentProvider(): array
    {
        return [
            'onload' => ['<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>', true],
            'mixed case' => ['<svg xmlns="http://www.w3.org/2000/svg"><rect onClick="alert(1)"/></svg>', true],
            'namespaced' => ['<svg xmlns="http://www.w3.org/2000/svg" xmlns:x="urn:x"><rect x:onclick="alert(1)"/></svg>', true],
            'data-onclick' => ['<svg xmlns="http://www.w3.org/2000/svg"><rect data-onclick="1"/></svg>', false],
        ];
    }

    /**
     * The document check alone, so event handlers stay rejected even if the
     * pattern that also catches them changes.
     */
    #[DataProvider('eventHandlerDocumentProvider')]
    public function test_document_check_rejects_event_handler_attributes(string $svg, bool $unsafe): void
    {
        $method = new \ReflectionMethod($this->handler, 'isUnsafeDocument');

        $this->assertSame($unsafe, $method->invoke($this->handler, $svg));
    }

    public static function unsafeStructureProvider(): array
    {
        $svg = fn (string $inner, string $attributes = '') => '<svg xmlns="http://www.w3.org/2000/svg"'.$attributes.'>'.$inner.'</svg>';

        return [
            'doctype' => ['<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"></svg>'],
            'xml-stylesheet instruction' => ['<?xml-stylesheet type="text/xsl" href="#t"?>'.$svg('')],
            'instruction inside the document' => [$svg('<?php echo 1; ?>')],
            'prefixed XHTML element' => [$svg('<h:p xmlns:h="http://www.w3.org/1999/xhtml">x</h:p>')],
            'XHTML default namespace' => [$svg('<div xmlns="http://www.w3.org/1999/xhtml">x</div>')],
            'MathML' => [$svg('<math xmlns="http://www.w3.org/1998/Math/MathML"><mi>x</mi></math>')],
            'XSLT element' => [$svg('<xsl:template xmlns:xsl="http://www.w3.org/1999/XSL/Transform" match="/"/>')],
            'iframe in another namespace' => [$svg('<x:iframe xmlns:x="urn:x"/>')],
            'object in another namespace' => [$svg('<x:object xmlns:x="urn:x"/>')],
            'embed in another namespace' => [$svg('<x:embed xmlns:x="urn:x"/>')],
            'foreignObject in another namespace' => [$svg('<x:foreignObject xmlns:x="urn:x"/>')],
            'animation targeting an event handler' => [$svg('<rect><set attributeName="onclick" to="x"/></rect>')],
        ];
    }

    /**
     * The document check alone, so these stay rejected even where a pattern
     * also catches them.
     */
    #[DataProvider('unsafeStructureProvider')]
    public function test_document_check_rejects_unsafe_structure(string $svg): void
    {
        $method = new \ReflectionMethod($this->handler, 'isUnsafeDocument');

        $this->assertTrue($method->invoke($this->handler, $svg));
    }

    public static function editorMetadataProvider(): array
    {
        return [
            'XMP metadata' => ['<svg xmlns="http://www.w3.org/2000/svg"><metadata><?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"/><?xpacket end="w"?></metadata><rect width="1" height="1"/></svg>'],
            'Inkscape and RDF' => ['<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/" inkscape:version="1.3"><sodipodi:namedview id="view" inkscape:zoom="1"/><metadata><rdf:RDF><rdf:Description><dc:title>Icon</dc:title></rdf:Description></rdf:RDF></metadata><rect width="1" height="1"/></svg>'],
            'Illustrator' => ['<svg xmlns="http://www.w3.org/2000/svg" xmlns:i="http://ns.adobe.com/AdobeIllustrator/10.0/"><i:pgf id="adobe_illustrator_pgf"/><rect width="1" height="1"/></svg>'],
            'animation of a presentation attribute' => ['<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"><animate attributeName="opacity" from="0" to="1" dur="1s"/></rect></svg>'],
        ];
    }

    #[DataProvider('editorMetadataProvider')]
    public function test_is_valid_svg_accepts_editor_metadata(string $svg): void
    {
        $this->assertTrue($this->handler->isValidSvg($svg));
    }
}
