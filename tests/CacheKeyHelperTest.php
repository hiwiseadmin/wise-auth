<?php
/**
 * CacheKeyHelper Trait 单元测试
 *
 * 测试缓存键生成逻辑。
 */
namespace wise\auth\tests;

use wise\auth\traits\CacheKeyHelper;

class CacheKeyHelperTest extends TestCase
{
    /**
     * 获取一个使用了 CacheKeyHelper Trait 的匿名类实例
     *
     * @return object
     */
    private function createTraitUser()
    {
        return new class {
            use CacheKeyHelper;

            public function publicGetCacheKey(string $key): string
            {
                return $this->getCacheKey($key);
            }
        };
    }

    public function testGetCacheKeyDefaultPrefix(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('test_key');
        $this->assertEquals('wiseauth:test_key', $key);
    }

    public function testGetCacheKeyWithUserType(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('user_perms:admin:1');
        $this->assertEquals('wiseauth:user_perms:admin:1', $key);
    }

    public function testGetCacheKeyEmptyKey(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('');
        $this->assertEquals('wiseauth:', $key);
    }

    public function testGetCacheKeyCustomPrefix(): void
    {
        $this->setConfig('wise-auth.cache_prefix', 'custom:');
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('test_key');
        $this->assertEquals('custom:test_key', $key);
    }

    /**
     * 缓存键**不**拼接数据库表前缀
     *
     * 站点间隔离靠 cache_prefix / store 落点（runtime 目录、Redis 前缀），
     * 表前缀是数据库层概念，混进缓存键只会在改前缀时产生一堆永不命中的孤儿键。
     */
    public function testGetCacheKeyDoesNotInjectTablePrefix(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('user_perms:admin:1');
        $this->assertEquals('wiseauth:user_perms:admin:1', $key);
        $this->assertStringNotContainsString('ws_', $key);
    }

    public function testGetCacheKeyCustomPrefixOnly(): void
    {
        $this->setConfig('wise-auth.cache_prefix', 'myapp:');
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('permission_map');
        $this->assertEquals('myapp:permission_map', $key);
    }

    public function testGetCacheKeyResultIsString(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('test');
        $this->assertIsString($key);
    }

    public function testGetCacheKeyStartsWithPrefix(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('any_key');
        $this->assertStringStartsWith('wiseauth:', $key);
    }

    public function testGetCacheKeyNumericKey(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('123');
        $this->assertEquals('wiseauth:123', $key);
    }

    public function testGetCacheKeySpecialCharacters(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('route_match:' . md5('/admin/users:GET'));
        $this->assertStringStartsWith('wiseauth:route_match:', $key);
        $this->assertGreaterThan(50, strlen($key));
    }
}
