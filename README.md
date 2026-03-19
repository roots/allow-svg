# Allow SVG

<a href="https://packagist.org/packages/roots/allow-svg"><img alt="Packagist Downloads" src="https://img.shields.io/packagist/dt/roots/allow-svg?label=downloads&colorB=2b3072&colorA=525ddc&style=flat-square"></a>
<a href="https://github.com/roots/allow-svg/actions/workflows/tests.yml"><img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/roots/allow-svg/tests.yml?branch=main&logo=github&label=CI&style=flat-square"></a>
<a href="https://twitter.com/rootswp"><img alt="Follow Roots" src="https://img.shields.io/badge/follow%20@rootswp-1da1f2?logo=twitter&logoColor=ffffff&message=&style=flat-square"></a>
<a href="https://github.com/sponsors/roots"><img src="https://img.shields.io/badge/sponsor%20roots-525ddc?logo=github&style=flat-square&logoColor=ffffff&message=" alt="Sponsor Roots"></a>

A WordPress plugin that enables SVG uploads with validation to block malicious files.

> WordPress still lacks native SVG support after [12+ years of discussion](https://core.trac.wordpress.org/ticket/24251)

## Support us

Roots is an independent open source org, supported only by developers like you. Your sponsorship funds [WP Packages](https://wp-packages.org/) and the entire Roots ecosystem, and keeps them independent. Support us by purchasing [Radicle](https://roots.io/radicle/) or [sponsoring us on GitHub](https://github.com/sponsors/roots) — sponsors get access to our private Discord.

## Features

- ✅ **SVG Upload Support** — Enables `.svg` uploads in the WordPress media library
- 🔒 **Security-First Validation** — Detects and rejects SVG files containing potentially harmful content
- 🖼️ **Media Library Integration** — SVGs display inline like standard images
- 🧩 **Zero Dependencies** — No external libraries or frameworks
- ⚙️ **Zero Configuration** — No settings or admin bloat

## Requirements

- PHP 8.2 or higher
- WordPress 5.9 or higher

## Installation

### via Composer

```bash
composer require roots/allow-svg
```

<details>
<summary>Install as a mu-plugin</summary>

If you are using [Bedrock](https://roots.io/bedrock/), you can install this as a must-use plugin by modifying your `composer.json` to install the package to the `mu-plugins` directory.

```json
{
    "extra": {
        "installer-paths": {
            "web/app/mu-plugins/{$name}/": [
                "type:wordpress-muplugin",
                "roots/allow-svg"
            ]
        }
    }
}
```

</details>

### Manual

1. Download `allow-svg.php`
2. Place in `wp-content/plugins/allow-svg/`
3. Activate via wp-admin or WP-CLI

## Usage

Once activated, the plugin automatically:

1. Enables SVG uploads through the Media Library or block editor
2. Performs strict validation on all SVG files
3. Rejects malicious files with clear error messages
4. Accepts clean, standards-compliant SVGs as-is

No configuration required.

## Security

This plugin uses a **deny-first approach**: it doesn't attempt to sanitize SVGs, it rejects files that appear unsafe.

### Accepts:

- Basic SVG shapes, paths, text, and inline styles
- ViewBox and standard attributes

### Rejects:

- `<script>` tags or inline JavaScript
- Event handlers like `onclick`, `onload`, etc.
- External references (`href`, `xlink:href`, `iframe`, `object`, `embed`)
- CSS expressions and `@import` rules
- Data URLs containing script or HTML content

### XML Hardening:

- **XXE Protection** — Blocks `<!DOCTYPE>` and external entity declarations
- **Entity Expansion Limits** — Rejects suspicious `&entity;` usage
- Uses `DOMDocument` with external entities disabled

## Community

Keep track of development and community news.

- Join us on Discord by [sponsoring us on GitHub](https://github.com/sponsors/roots)
- Join us on [Roots Discourse](https://discourse.roots.io/)
- Follow [@rootswp on Twitter](https://twitter.com/rootswp)
- Follow the [Roots Blog](https://roots.io/blog/)
- Subscribe to the [Roots Newsletter](https://roots.io/subscribe/)
