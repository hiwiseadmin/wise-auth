<?php
declare(strict_types=1);

namespace wise\login\captcha;

use think\App;
use think\facade\Cache;

/**
 * 基于 GD 库的图片验证码驱动
 *
 * 配置项：config('wise-auth.login.captcha')
 *  - length: 字符长度
 *  - charset: digits / letters / mix
 *  - expire: 有效期（秒）
 *  - width / height: 图片尺寸
 *  - font_size: 字体大小（使用 TrueType 字体时实际生效；无字体时限制为 1-5）
 *  - font_path: TrueType 字体文件路径（可选，不设则自动检测系统字体）
 *  - noise_dots / noise_lines: 干扰元素
 *  - distortion: 扭曲度 0-1
 *  - cache_prefix: 缓存前缀
 */
class GdCaptchaDriver implements CaptchaDriverInterface
{
    public function __construct(protected App $app)
    {
    }

    public function getName(): string
    {
        return 'gd';
    }

    public function generate(): array
    {
        if (!extension_loaded('gd')) {
            throw new \RuntimeException('GD extension is required for GdCaptchaDriver');
        }

        $cfg = $this->config();
        $length = max(1, (int) ($cfg['length'] ?? 4));
        $width  = (int) ($cfg['width'] ?? 130);
        $height = (int) ($cfg['height'] ?? 50);
        $fontSize = (int) ($cfg['font_size'] ?? 20);

        $code = $this->randomCode($length, (string) ($cfg['charset'] ?? 'mix'));

        $img = imagecreatetruecolor($width, $height);
        $bgColor = imagecolorallocate($img, 240, 240, 240);
        imagefilledrectangle($img, 0, 0, $width, $height, $bgColor);

        $noiseDots = (int) ($cfg['noise_dots'] ?? 80);
        for ($i = 0; $i < $noiseDots; $i++) {
            $color = imagecolorallocate($img, mt_rand(150, 220), mt_rand(150, 220), mt_rand(150, 220));
            imagesetpixel($img, mt_rand(0, $width), mt_rand(0, $height), $color);
        }

        $noiseLines = (int) ($cfg['noise_lines'] ?? 3);
        for ($i = 0; $i < $noiseLines; $i++) {
            $color = imagecolorallocate($img, mt_rand(100, 200), mt_rand(100, 200), mt_rand(100, 200));
            imageline(
                $img,
                mt_rand(0, $width),
                mt_rand(0, $height),
                mt_rand(0, $width),
                mt_rand(0, $height),
                $color
            );
        }

        $distortion = (float) ($cfg['distortion'] ?? 0.3);
        $fontPath = $this->resolveFontPath((string) ($cfg['font_path'] ?? ''));

        if ($fontPath !== null && function_exists('imagettftext')) {
            $x = (int) (($width - ($length * ($fontSize * 0.7))) / 2);
            for ($i = 0; $i < $length; $i++) {
                $color = imagecolorallocate($img, mt_rand(0, 100), mt_rand(0, 100), mt_rand(0, 100));
                if ($color === false) {
                    $color = 0;
                }
                $y = mt_rand((int) ($height * 0.5), (int) ($height * 0.8));

                $offsetX = (int) (mt_rand(intval(-$distortion * 5), intval($distortion * 5)));
                $offsetY = (int) (mt_rand(intval(-$distortion * 3), intval($distortion * 3)));

                $angle = (int) (mt_rand(intval(-$distortion * 15), intval($distortion * 15)));

                imagettftext($img, $fontSize, $angle, $x + $offsetX, $y + $offsetY, $color, $fontPath, $code[$i]);

                $x += (int) ($fontSize * 0.9);
            }
        } else {
            $actualSize = min(5, max(1, $fontSize));
            $charWidth  = imagefontwidth($actualSize);
            $charHeight = imagefontheight($actualSize);
            $x = (int) (($width - ($length * $charWidth)) / 2);
            for ($i = 0; $i < $length; $i++) {
                $color = imagecolorallocate($img, mt_rand(0, 100), mt_rand(0, 100), mt_rand(0, 100));
                $y = mt_rand((int) ($height * 0.3), (int) ($height * 0.7));

                $offsetX = (int) (mt_rand(intval(-$distortion * 5), intval($distortion * 5)));
                $offsetY = (int) (mt_rand(intval(-$distortion * 3), intval($distortion * 3)));

                imagestring($img, $actualSize, $x + $offsetX, $y + $offsetY - (int) ($charHeight / 2), $code[$i], $color);

                $x += $charWidth + (int) ($charWidth * 0.3);
            }
        }

        $borderColor = imagecolorallocate($img, 200, 200, 200);
        imagerectangle($img, 0, 0, $width - 1, $height - 1, $borderColor);

        $stream = fopen('php://temp', 'wb+');
        if ($stream === false) {
            imagedestroy($img);
            throw new \RuntimeException('验证码图片生成失败：无法创建临时流');
        }

        try {
            imagepng($img, $stream);
            rewind($stream);
            $bin = (string) stream_get_contents($stream);
        } finally {
            fclose($stream);
            imagedestroy($img);
        }

        $dataUri = 'data:image/png;base64,' . base64_encode($bin);

        $key = $this->randomKey();
        $expire = (int) ($cfg['expire'] ?? 300);
        $prefix = (string) ($cfg['cache_prefix'] ?? 'wise_login_security:captcha:');
        Cache::set($prefix . $key, strtolower($code), $expire);

        return [
            'image'  => $dataUri,
            'key'    => $key,
            'mime'   => 'image/png',
            'expire' => time() + $expire
        ];
    }

    public function verify(string $key, string $input): bool
    {
        if ($key === '' || $input === '') {
            return false;
        }
        $prefix = (string) ($this->config()['cache_prefix'] ?? 'wise_login_security:captcha:');
        $cached = Cache::get($prefix . $key);
        if ($cached === null || $cached === false) {
            return false;
        }
        Cache::delete($prefix . $key);
        return strtolower(trim((string) $input)) === strtolower((string) $cached);
    }

    /**
     * 按字符集生成随机验证码字符串（使用 random_int）
     *
     * @param int    $length  字符长度
     * @param string $charset digits | letters | mix
     * @return string
     */
    protected function randomCode(int $length, string $charset): string
    {
        $pool = match ($charset) {
            'digits'  => '0123456789',
            'letters' => 'ABCDEFGHJKLMNPQRSTUVWXYZ',
            default   => '23456789ABCDEFGHJKLMNPQRSTUVWXYZ',
        };
        $code = '';
        $max = strlen($pool) - 1;
        for ($i = 0; $i < $length; $i++) {
            $code .= $pool[random_int(0, $max)];
        }
        return $code;
    }

    /**
     * 生成随机缓存键（32 字符 hex）
     *
     * @return string
     */
    protected function randomKey(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * 解析 TrueType 字体文件路径。
     * 优先级：配置的 font_path > 系统常见字体路径自动检测 > null（退回 imagestring）
     */
    protected function resolveFontPath(string $configuredPath): ?string
    {
        if ($configuredPath !== '' && file_exists($configuredPath)) {
            return $configuredPath;
        }

        $projectFont = $this->app->getRootPath() . 'public' . DIRECTORY_SEPARATOR . 'fonts' . DIRECTORY_SEPARATOR . 'captcha.ttf';
        if (file_exists($projectFont)) {
            return $projectFont;
        }

        $candidates = [
            'C:/Windows/Fonts/arial.ttf',
            'C:/Windows/Fonts/verdanai.ttf',
            '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
            '/usr/share/fonts/truetype/droid/DroidSans.ttf',
            '/usr/share/fonts/truetype/freefont/FreeSans.ttf',
            '/System/Library/Fonts/Supplemental/Arial.ttf',
            '/Library/Fonts/Arial.ttf',
        ];

        foreach ($candidates as $candidate) {
            if (file_exists($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * 获取验证码配置
     *
     * @return array
     */
    protected function config(): array
    {
        return (array) $this->app->config->get('wise-auth.login.captcha', []);
    }
}
