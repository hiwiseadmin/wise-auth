<?php
/**
 * PermissionRegistrar 单元测试
 *
 * 测试权限注册、#[AuthPermission] 扫描解析、缓存管理等核心方法。
 */
namespace wise\auth\tests;

use Mockery;
use wise\auth\attribute\AuthPermission;
use wise\auth\service\PermissionRegistrar;

class PermissionRegistrarTest extends TestCase
{
    /** @var PermissionRegistrar */
    protected $registrar;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setConfig('wise-auth.cache_enabled', false);
        $this->registrar = new PermissionRegistrar();
    }


    public function testAttributeToArrayKeepsExplicitValuesOnly(): void
    {
        $attribute = new AuthPermission(ident: 'admin.user.list', name: '管理员列表');

        $this->assertSame(
            ['ident' => 'admin.user.list', 'name' => '管理员列表'],
            $attribute->toArray()
        );
    }

    public function testAttributeToArrayKeepsZeroAndEmptyString(): void
    {
        $attribute = new AuthPermission(ident: 'admin.user.list', status: 0, description: '');

        $data = $attribute->toArray();

        $this->assertArrayHasKey('status', $data);
        $this->assertSame(0, $data['status']);
        $this->assertArrayHasKey('description', $data);
        $this->assertSame('', $data['description']);
    }


    public function testParseAttributePermissionsReadsMethodAttributes(): void
    {
        $result = $this->invokeMethod(
            $this->registrar,
            'parseAttributePermissions',
            [__DIR__ . '/fixtures/AuthPermissionController.php']
        );

        $idents = array_column($result, 'ident');

        $this->assertSame(['admin.user.list', 'admin.user.create', 'admin.user.export'], $idents);
    }

    public function testParseAttributePermissionsAppliesClassLevelDefaults(): void
    {
        $result = $this->invokeMethod(
            $this->registrar,
            'parseAttributePermissions',
            [__DIR__ . '/fixtures/AuthPermissionController.php']
        );

        foreach ($result as $permission) {
            $this->assertSame('route', $permission['type']);
            $this->assertSame('admin.user', $permission['parent']);
        }
    }

    public function testParseAttributePermissionsMethodLevelOverridesDefaults(): void
    {
        $result = $this->invokeMethod(
            $this->registrar,
            'parseAttributePermissions',
            [__DIR__ . '/fixtures/AuthPermissionController.php']
        );

        $create = array_values(array_filter($result, static fn ($item) => $item['ident'] === 'admin.user.create'))[0];

        $this->assertSame('POST', $create['method']);
        $this->assertSame('/admin/users/create', $create['route']);
        $this->assertSame('新增管理员', $create['name']);
    }

    public function testParseAttributePermissionsSkipsMissingIdent(): void
    {
        $result = $this->invokeMethod(
            $this->registrar,
            'parseAttributePermissions',
            [__DIR__ . '/fixtures/AuthPermissionController.php']
        );

        $names = array_column($result, 'name');
        $this->assertNotContains('缺少 ident 的声明', $names);
        $this->assertCount(3, $result);
    }

    public function testParseAttributePermissionsReturnsEmptyForControllerWithoutAttributes(): void
    {
        $result = $this->invokeMethod(
            $this->registrar,
            'parseAttributePermissions',
            [__DIR__ . '/fixtures/PlainController.php']
        );

        $this->assertSame([], $result);
    }

    public function testParseAttributePermissionsReturnsEmptyForInvalidFile(): void
    {
        $result = $this->invokeMethod(
            $this->registrar,
            'parseAttributePermissions',
            ['/nonexistent/file_that_does_not_exist.php']
        );

        $this->assertSame([], $result);
    }


    public function testResolveClassNameReturnsFullyQualifiedName(): void
    {
        $class = $this->invokeMethod(
            $this->registrar,
            'resolveClassName',
            [__DIR__ . '/fixtures/AuthPermissionController.php']
        );

        $this->assertSame(\wise\auth\tests\fixtures\AuthPermissionController::class, $class);
    }

    public function testResolveClassNameIgnoresClassConstantAndAnonymousClass(): void
    {
        $code = <<<'PHP'
<?php
namespace demo\ctl;

class Demo
{
    public function name(): string
    {
        $anon = new class {
        };
        return self::class;
    }
}
PHP;

        $tmpFile = tempnam(sys_get_temp_dir(), 'wiseauth_test_');
        file_put_contents($tmpFile, $code);
        try {
            $class = $this->invokeMethod($this->registrar, 'resolveClassName', [$tmpFile]);
            $this->assertSame('demo\ctl\Demo', $class);
        } finally {
            @unlink($tmpFile);
        }
    }

    public function testResolveClassNameReturnsNullWithoutClass(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'wiseauth_test_');
        file_put_contents($tmpFile, "<?php\n// no class here\n");
        try {
            $this->assertNull($this->invokeMethod($this->registrar, 'resolveClassName', [$tmpFile]));
        } finally {
            @unlink($tmpFile);
        }
    }


    public function testHasPermissionUsesGetPermissionMap(): void
    {
        $this->registrar = Mockery::mock(PermissionRegistrar::class)->makePartial();
        $this->registrar->shouldReceive('getPermissionMap')->andReturn([
            'admin.user.list' => ['id' => 1, 'ident' => 'admin.user.list'],
            'admin.user.create' => ['id' => 2, 'ident' => 'admin.user.create'],
        ]);

        $this->assertTrue($this->registrar->hasPermission('admin.user.list'));
        $this->assertTrue($this->registrar->hasPermission('admin.user.create'));
        $this->assertFalse($this->registrar->hasPermission('admin.user.delete'));
        $this->assertFalse($this->registrar->hasPermission('nonexistent'));
    }


    public function testRegistrarUsesCacheKeyHelper(): void
    {
        $traits = class_uses($this->registrar);
        $this->assertArrayHasKey(\wise\auth\traits\CacheKeyHelper::class, $traits);
    }

    public function testRegistrarGetCacheKey(): void
    {
        $key = $this->invokeMethod($this->registrar, 'getCacheKey', ['permission_map']);
        $this->assertEquals('wiseauth:permission_map', $key);
    }
}
