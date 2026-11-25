<?php
declare(strict_types=1);

namespace wise\login\facade;

use think\Facade;
use wise\login\event\EventLogger;

/**
 * @see EventLogger
 *
 * 用法：
 *   \wise\login\facade\Logger::log('login_failure', ['username' => 'foo']);
 *
 * @method static void log(string $type, array $data = [], ?\think\Request $request = null, ?string $username = null) 记录一条事件
 */
class Logger extends Facade
{
    protected static function getFacadeClass(): string
    {
        return EventLogger::class;
    }
}
