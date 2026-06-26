<?php
/**
 * CacheKeyHelper Trait 单元测试
 *
 * 测试缓存键生成逻辑。
 */
namespace wise\auth\tests;

use wise\auth\trait\CacheKeyHelper;

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

            /** 暴露 protected 方法供测试 */
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
        $this->setConfig('wiseauth.cache_prefix', 'custom:');
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('test_key');
        $this->assertEquals('custom:test_key', $key);
    }

    public function testGetCacheKeyWithTablePrefix(): void
    {
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('user_perms:admin:1');
        $this->assertEquals('wiseauth:ws_user_perms:admin:1', $key);
    }

    public function testGetCacheKeyCustomPrefixAndTablePrefix(): void
    {
        $this->setConfig('wiseauth.cache_prefix', 'myapp:');
        $user = $this->createTraitUser();
        $key = $user->publicGetCacheKey('permission_map');
        $this->assertEquals('myapp:prefix_permission_map', $key);
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
        // prefix(7) + "route_match:"(12) + md5(32) = 51
        $this->assertGreaterThan(50, strlen($key));
    }
}
