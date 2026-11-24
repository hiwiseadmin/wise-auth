<?php
declare(strict_types=1);

namespace wise\login\totp;

/**
 * Base32 编码 / 解码（RFC 4648）
 *
 * 用于 TOTP 密钥的字符串表示，避免在 QR 中出现不易识别的字符
 */
class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $bytes): string
    {
        $output = '';
        $buffer = 0;
        $bitsLeft = 0;

        for ($i = 0, $n = strlen($bytes); $i < $n; $i++) {
            $buffer = ($buffer << 8) | ord($bytes[$i]);
            $bitsLeft += 8;
            while ($bitsLeft >= 5) {
                $bitsLeft -= 5;
                $index = ($buffer >> $bitsLeft) & 0x1F;
                $output .= self::ALPHABET[$index];
            }
        }

        if ($bitsLeft > 0) {
            $index = ($buffer << (5 - $bitsLeft)) & 0x1F;
            $output .= self::ALPHABET[$index];
        }

        $padLen = (8 - strlen($output) % 8) % 8;
        if ($padLen > 0) {
            $output .= str_repeat('=', $padLen);
        }

        return $output;
    }

    public static function decode(string $input): string
    {
        $input = strtoupper(rtrim($input, '='));
        $input = preg_replace('/\s+/', '', $input);
        $output = '';
        $buffer = 0;
        $bitsLeft = 0;

        for ($i = 0, $n = strlen($input); $i < $n; $i++) {
            $char = $input[$i];
            if ($char === ' ' || $char === '=') {
                continue;
            }
            $idx = strpos(self::ALPHABET, $char);
            if ($idx === false) {
                throw new \InvalidArgumentException("Invalid base32 character: {$char}");
            }
            $buffer = ($buffer << 5) | $idx;
            $bitsLeft += 5;
            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }
        return $output;
    }
}
