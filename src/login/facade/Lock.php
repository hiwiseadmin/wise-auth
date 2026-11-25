<?php
declare(strict_types=1);

namespace wise\login\facade;

use think\Facade;
use wise\login\lock\LoginLockManager;

/**
 * @see LoginLockManager
 *
 * @method static bool isLocked(?string $username, string $ip)
 * @method static array recordFailure(?string $username, string $ip)
 * @method static void clear(?string $username, string $ip)
 * @method static void lock(?string $username, string $ip, int $minutes = 0)
 * @method static void unlock(?string $username, string $ip)
 */
class Lock extends Facade
{
    protected static function getFacadeClass(): string
    {
        return LoginLockManager::class;
    }
}
