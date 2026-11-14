<?php

declare(strict_types=1);

namespace Plumbline\Project;

use PhpParser\Parser;
use PhpParser\ParserFactory;
use Symfony\Component\Finder\Finder;

/** A loaded Laravel project: its PHP files, Blade templates, env files and lazily-built indexes. */
final class Project
{
    public const DEFAULT_EXCLUDES = [
        'vendor', 'node_modules', 'storage', 'bootstrap/cache', 'tests', 'public/build', 'public/vendor', '.git',
        'var', 'tmp', '.idea', '.vscode', '.claude', '.cursor', '.fleet', '.phpunit.cache', 'coverage', '.github',
    ];

    /** Generated files (compiled containers, caches) are not worth parsing. */
    private const MAX_FILE_BYTES = 1_000_000;

    /** @var list<PhpFile> */
    private array $phpFiles = [];

    /** @var array<string, PhpFile> */
    private array $byRelative = [];

    /** @var list<BladeFile> */
    private array $bladeFiles = [];

    /** @var array<string, string> relative path => contents */
    private array $envFiles = [];

    private ?ClassIndex $classes = null;

    private ?ModelIndex $models = null;

    private ?RouteIndex $routes = null;

    /** @param list<string> $excludes */
    public function __construct(public readonly string $root, array $excludes = self::DEFAULT_EXCLUDES)
    {
        $parser = (new ParserFactory())->createForNewestSupportedVersion();
        $this->load($parser, $excludes);
    }

    /** @var list<string> embedded third-party apps that were skipped */
    private array $embedded = [];

    /** @return list<string> */
    public function skippedEmbeddedApps(): array
    {
        return $this->embedded;
    }

    /**
     * A nested directory with its own vendor/autoload.php is a separately installed PHP application
     * (a bundled forum, a legacy app) rather than this app's code. Its root is skipped: when the
     * vendor directory sits in a "src" folder, the folder above it.
     *
     * @param list<string> $excludes
     * @return list<string>
     */
    private function detectEmbeddedApps(array $excludes): array
    {
        $out = [];
        $dirs = (new Finder())->directories()->in($this->root)->exclude($excludes)->depth('<= 3')->ignoreDotFiles(true);
        foreach ($dirs as $dir) {
            if (! is_file($dir->getPathname().DIRECTORY_SEPARATOR.'vendor'.DIRECTORY_SEPARATOR.'autoload.php')) {
                continue;
            }
            $relative = str_replace('\\', '/', $dir->getRelativePathname());
            if (basename($relative) === 'src' && str_contains($relative, '/')) {
                $relative = dirname($relative);
            }
            $out[] = $relative;
        }

        return array_values(array_unique($out));
    }

    /** @param list<string> $excludes */
    private function load(Parser $parser, array $excludes): void
    {
        $this->embedded = $this->detectEmbeddedApps($excludes);
        $excludes = array_merge($excludes, $this->embedded);

        $finder = (new Finder())
            ->files()
            ->in($this->root)
            ->ignoreDotFiles(false)
            ->ignoreVCS(true)
            ->exclude($excludes)
            ->name(['*.php', '.env', '.env.*'])
            ->size('<= '.self::MAX_FILE_BYTES)
            ->sortByName();

        foreach ($finder as $file) {
            $relative = str_replace('\\', '/', $file->getRelativePathname());
            $contents = $file->getContents();
            $basename = $file->getFilename();

            if (str_starts_with($basename, '.env')) {
                // Only root-level env files describe this app's configuration.
                if (! str_contains($relative, '/')) {
                    $this->envFiles[$relative] = $contents;
                }
            } elseif (str_ends_with($basename, '.blade.php')) {
                $this->bladeFiles[] = new BladeFile($file->getPathname(), $relative, $contents);
            } else {
                $php = new PhpFile($file->getPathname(), $relative, $contents, $parser);
                $this->phpFiles[] = $php;
                $this->byRelative[$relative] = $php;
            }
        }
    }

    /** @return list<PhpFile> */
    public function phpFiles(): array
    {
        return $this->phpFiles;
    }

    public function file(string $relative): ?PhpFile
    {
        return $this->byRelative[str_replace('\\', '/', $relative)] ?? null;
    }

    /** @return list<BladeFile> */
    public function bladeFiles(): array
    {
        return $this->bladeFiles;
    }

    /** @return array<string, string> */
    public function envFiles(): array
    {
        return $this->envFiles;
    }

    public function classes(): ClassIndex
    {
        return $this->classes ??= new ClassIndex($this->phpFiles);
    }

    public function models(): ModelIndex
    {
        return $this->models ??= new ModelIndex($this);
    }

    public function routes(): RouteIndex
    {
        return $this->routes ??= new RouteIndex($this);
    }

    /** True when the root looks like a Laravel application or package. */
    public function looksLikeLaravel(): bool
    {
        if (is_file($this->root.DIRECTORY_SEPARATOR.'artisan')) {
            return true;
        }
        $composer = $this->root.DIRECTORY_SEPARATOR.'composer.json';
        if (! is_file($composer)) {
            return false;
        }
        $json = json_decode((string) file_get_contents($composer), true);
        $requires = is_array($json) ? array_merge((array) ($json['require'] ?? []), (array) ($json['require-dev'] ?? [])) : [];
        foreach (array_keys($requires) as $package) {
            if (str_starts_with((string) $package, 'laravel/') || str_starts_with((string) $package, 'illuminate/')) {
                return true;
            }
        }

        return false;
    }
}
