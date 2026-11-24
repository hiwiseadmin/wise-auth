<?php
/**
 * WiseAuth 单元测试基类
 *
 * 提供 Mockery 集成、配置管理和通用辅助方法。
 */
namespace wise\auth\tests;

use PHPUnit\Framework\TestCase as PHPUnitTestCase;
use Mockery;

abstract class TestCase extends PHPUnitTestCase
{
    /**
     * 测试配置
     *
     * @var array
     */
    protected $testConfig = [];

    /**
     * 设置测试环境
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->testConfig = [
            'wise-auth' => [
                'default_user_model'     => \wise\auth\tests\stubs\TestUser::class,
                'user_models'            => [],
                'super_role'             => 'super_admin',
                'super_admin_ids'        => [1],
                'cache_enabled'          => true,
                'cache_store'            => null,
                'cache_ttl'              => 3600,
                'cache_prefix'           => 'wiseauth:',
                'permission_sources'     => ['database'],
                'attribute_dirs'         => [],
                'permissions'            => [],
                'default_mode'           => 'whitelist',
                'whitelist_routes'       => ['/admin/login', '/admin/logout', '/admin/auth/*'],
                'blacklist_routes'       => [],
                'unauthorized_action'    => 'json',
                'unauthorized_redirect'  => '/admin/login',
                'unauthorized_handler'   => null,
                'inheritance_enabled'    => true,
                'inheritance_max_depth'  => 10,
                'cycle_check_enabled'    => true,
                'constraint_checker'     => null,
                'constraints'            => [],
                'middleware_check_type'  => 'or',
                'middleware_auth_check'  => true,
                'user_resolver'          => null,
                'middleware_trust_auth_user_id' => false,
                'data_policy'            => null,
            ],
        ];

        $GLOBALS['_test_config'] = $this->testConfig;

        \wise\auth\service\RbacManager::resetSuperAdminIdsCache();
    }

    /**
     * 清理 Mockery
     */
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    /**
     * 设置配置值
     *
     * @param string $key   配置键（支持点号分隔，如 'wise-auth.cache_enabled'）
     * @param mixed  $value 配置值
     */
    protected function setConfig(string $key, $value): void
    {
        $keys = explode('.', $key);
        $config = &$this->testConfig;
        foreach ($keys as $k) {
            if (!isset($config[$k])) {
                $config[$k] = [];
            }
            $config = &$config[$k];
        }
        $config = $value;
        $GLOBALS['_test_config'] = $this->testConfig;
    }

    /**
     * 获取配置值
     *
     * @param string $key
     * @param mixed  $default
     * @return mixed
     */
    protected function getConfig(string $key, $default = null)
    {
        $keys = explode('.', $key);
        $value = $this->testConfig;
        foreach ($keys as $k) {
            if (!is_array($value) || !array_key_exists($k, $value)) {
                return $default;
            }
            $value = $value[$k];
        }
        return $value;
    }

    /**
     * 调用 protected/private 方法
     *
     * @param object $object
     * @param string $method
     * @param array  $args
     * @return mixed
     */
    protected function invokeMethod($object, string $method, array $args = [])
    {
        $reflection = new \ReflectionClass($object);
        $method = $reflection->getMethod($method);
        $method->setAccessible(true);
        return $method->invokeArgs($object, $args);
    }

    /**
     * 获取 protected/private 属性值
     *
     * @param object $object
     * @param string $property
     * @return mixed
     */
    protected function getProperty($object, string $property)
    {
        $reflection = new \ReflectionClass($object);
        $prop = $reflection->getProperty($property);
        $prop->setAccessible(true);
        return $prop->getValue($object);
    }

    /**
     * 设置 protected/private 属性值
     *
     * @param object $object
     * @param string $property
     * @param mixed  $value
     */
    protected function setProperty($object, string $property, $value): void
    {
        $reflection = new \ReflectionClass($object);
        $prop = $reflection->getProperty($property);
        $prop->setAccessible(true);
        $prop->setValue($object, $value);
    }
}
