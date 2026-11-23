<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace CodeIgniter\Shield\Authentication\LDAP;

final class LdapFilter
{
    private const IDENTIFIER = '(?:[a-zA-Z][a-zA-Z0-9-]*|(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+)';
    private const ATTRIBUTE  = self::IDENTIFIER . '(?:;[a-zA-Z0-9-]+)*';

    public static function equal(string $attribute, string $value): string
    {
        self::validateAttribute($attribute);

        return '(' . $attribute . '=' . self::escapeValue($value) . ')';
    }

    public static function all(string ...$filters): string
    {
        return self::combine('&', $filters);
    }

    public static function any(string ...$filters): string
    {
        return self::combine('|', $filters);
    }

    public static function not(string $filter): string
    {
        self::validate($filter);

        return '(!' . $filter . ')';
    }

    public static function escapeValue(string $value): string
    {
        return preg_replace_callback('/[\x00-\x1f\x7f-\xff()*\x5c]/', self::hexEscape(...), $value)
            ?? throw new LdapException('invalid_filter_value');
    }

    public static function escapeDnComponent(string $value): string
    {
        return preg_replace_callback('/(^[ #]| $|[\x00-\x1f\x7f-\xff"+,;<>=\x5c])/', self::hexEscape(...), $value)
            ?? throw new LdapException('invalid_dn_component');
    }

    public static function validateAttribute(string $attribute): void
    {
        if (strlen($attribute) > 128 || preg_match('/\A' . self::ATTRIBUTE . '\z/', $attribute) !== 1) {
            throw new LdapException('invalid_attribute');
        }
    }

    public static function validate(string $filter): void
    {
        if (strlen($filter) > 16384 || preg_match('//u', $filter) !== 1 || self::parse($filter, 0, 0) !== strlen($filter)) {
            throw new LdapException('invalid_filter');
        }
    }

    /**
     * @param list<string> $filters
     */
    private static function combine(string $operator, array $filters): string
    {
        foreach ($filters as $filter) {
            self::validate($filter);
        }

        $combined = '(' . $operator . implode('', $filters) . ')';
        self::validate($combined);

        return $combined;
    }

    /**
     * @param non-empty-list<string> $match
     */
    private static function hexEscape(array $match): string
    {
        return '\\' . bin2hex($match[0]);
    }

    private static function parse(string $filter, int $offset, int $depth): int
    {
        if ($depth >= 32 || ($filter[$offset] ?? '') !== '(') {
            throw new LdapException('invalid_filter');
        }

        $offset++;
        $operator = $filter[$offset] ?? '';

        if ($operator === '&' || $operator === '|') {
            $offset++;

            do {
                $offset = self::parse($filter, $offset, $depth + 1);
            } while (($filter[$offset] ?? '') === '(');
        } elseif ($operator === '!') {
            $offset = self::parse($filter, $offset + 1, $depth + 1);
        } else {
            $length = strcspn($filter, '()', $offset);
            self::validateItem(substr($filter, $offset, $length));
            $offset += $length;
        }

        if (($filter[$offset] ?? '') !== ')') {
            throw new LdapException('invalid_filter');
        }

        return $offset + 1;
    }

    private static function validateItem(string $item): void
    {
        $delimiter = strpos($item, '=');

        if ($delimiter === false) {
            throw new LdapException('invalid_filter');
        }

        $left  = substr($item, 0, $delimiter);
        $value = substr($item, $delimiter + 1);

        if (str_ends_with($left, ':')) {
            $name = '(?:' . self::ATTRIBUTE . '(?::dn)?(?::' . self::IDENTIFIER . ')?|(?::dn)?:' . self::IDENTIFIER . ')';

            if (preg_match('/\A' . $name . ':\z/i', $left) !== 1) {
                throw new LdapException('invalid_filter');
            }

            self::validateValue($value, false);

            return;
        }

        if (preg_match('/\A' . self::ATTRIBUTE . '(?<operator>[~<>]?)\z/', $left, $matches) !== 1) {
            throw new LdapException('invalid_filter');
        }

        self::validateValue($value, $matches['operator'] === '');
    }

    private static function validateValue(string $value, bool $allowWildcard): void
    {
        $excluded = $allowWildcard ? '\x00()' : '\x00()*';

        if (preg_match('/\A(?:\x5c[0-9a-f]{2}|[^\x5c' . $excluded . '])*\z/i', $value) !== 1) {
            throw new LdapException('invalid_filter');
        }
    }
}
