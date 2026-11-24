<?php
declare(strict_types=1);

namespace wise\login\facade;

use think\Facade;
use wise\login\captcha\CaptchaManager;

/**
 * @see CaptchaManager
 *
 * @method static array generate()
 * @method static bool verify(string $key, string $input)
 */
class Captcha extends Facade
{
    protected static function getFacadeClass(): string
    {
        return CaptchaManager::class;
    }
}
