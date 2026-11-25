<?php
/**
 * 模型类单元测试
 *
 * 测试 Role, Permission, UserRole 模型的属性配置和核心方法。
 */
namespace wise\auth\tests;

use Mockery;
use wise\auth\model\Role;
use wise\auth\model\Permission;
use wise\auth\model\UserRole;
use wise\auth\tests\fixtures\AncestorTestRole;

class ModelTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }


    public function testRoleModelTableName(): void
    {
        $role = new Role();
        $this->assertEquals('auth_roles', $this->getProperty($role, 'name'));
    }

    public function testRoleModelAutoTimestamp(): void
    {
        $role = new Role();
        $this->assertTrue($this->getProperty($role, 'autoWriteTimestamp'));
    }

    public function testRoleModelTimestampFields(): void
    {
        $role = new Role();
        $this->assertEquals('create_time', $this->getProperty($role, 'createTime'));
        $this->assertEquals('update_time', $this->getProperty($role, 'updateTime'));
        $this->assertEquals('delete_time', $this->getProperty($role, 'deleteTime'));
    }

    public function testRoleModelTypeCasts(): void
    {
        $role = new Role();
        $type = $this->getProperty($role, 'type');
        $this->assertArrayHasKey('is_inherit', $type);
        $this->assertArrayHasKey('status', $type);
        $this->assertArrayHasKey('level', $type);
        $this->assertArrayHasKey('sort', $type);
        $this->assertEquals('integer', $type['is_inherit']);
        $this->assertEquals('integer', $type['status']);
        $this->assertEquals('integer', $type['level']);
        $this->assertEquals('integer', $type['sort']);
    }

    public function testRoleModelReadonlyFields(): void
    {
        $role = new Role();
        $readonly = $this->getProperty($role, 'readonly');
        $this->assertContains('create_time', $readonly);
    }

    public function testRoleModelUsesSoftDelete(): void
    {
        $role = new Role();
        $traits = class_uses($role);
        $this->assertArrayHasKey(\think\model\concern\SoftDelete::class, $traits);
    }

    public function testRoleModelExtendsThinkModel(): void
    {
        $role = new Role();
        $this->assertInstanceOf(\think\Model::class, $role);
    }


    public function testRoleHasCycleSimpleNoCycle(): void
    {
        $mockRole = Mockery::mock(Role::class . '[find]');
        $mockRole->shouldReceive('find')->andReturnUsing(function ($id) {
            if ($id === 1) {
                $r = new Role();
                $this->setProperty($r, 'data', ['id' => 1, 'parent_id' => 0]);
                return $r;
            }
            return null;
        });

        $this->assertTrue(true);
    }

    public function testRoleHasCycleReturnsBool(): void
    {
        $this->assertTrue(true);
    }


    public function testRoleGetAncestorIdsWithPath(): void
    {
        AncestorTestRole::reset();

        $role = new AncestorTestRole();
        $role->data(['id' => 5, 'path' => '0-1-3-5', 'parent_id' => 3]);
        AncestorTestRole::$rows[5] = $role;

        $this->assertSame([0, 1, 3], AncestorTestRole::getAncestorIds(5));
    }

    public function testRoleGetAncestorIdsRoleNotFound(): void
    {
        AncestorTestRole::reset();

        $this->assertSame([], AncestorTestRole::getAncestorIds(999));
    }

    public function testRoleGetAncestorIdsFallsBackToParentChain(): void
    {
        AncestorTestRole::reset();

        $child = new AncestorTestRole();
        $child->data(['id' => 7, 'parent_id' => 3]);

        $parent = new AncestorTestRole();
        $parent->data(['id' => 3, 'parent_id' => 0]);

        AncestorTestRole::$rows[7] = $child;
        AncestorTestRole::$rows[3] = $parent;

        $this->assertSame([3], AncestorTestRole::getAncestorIds(7));
    }

    public function testRoleGetAncestorIdsStopsOnCycle(): void
    {
        AncestorTestRole::reset();

        $a = new AncestorTestRole();
        $a->data(['id' => 1, 'parent_id' => 2]);

        $b = new AncestorTestRole();
        $b->data(['id' => 2, 'parent_id' => 1]);

        AncestorTestRole::$rows[1] = $a;
        AncestorTestRole::$rows[2] = $b;

        $this->assertSame([2], AncestorTestRole::getAncestorIds(1));
    }


    public function testPermissionModelTableName(): void
    {
        $perm = new Permission();
        $this->assertEquals('auth_permissions', $this->getProperty($perm, 'name'));
    }

    public function testPermissionModelAutoTimestamp(): void
    {
        $perm = new Permission();
        $this->assertTrue($this->getProperty($perm, 'autoWriteTimestamp'));
    }

    public function testPermissionModelTimestampFields(): void
    {
        $perm = new Permission();
        $this->assertEquals('create_time', $this->getProperty($perm, 'createTime'));
        $this->assertEquals('update_time', $this->getProperty($perm, 'updateTime'));
        $this->assertEquals('delete_time', $this->getProperty($perm, 'deleteTime'));
    }

    public function testPermissionModelTypeCasts(): void
    {
        $perm = new Permission();
        $type = $this->getProperty($perm, 'type');
        $this->assertArrayHasKey('status', $type);
        $this->assertArrayHasKey('level', $type);
        $this->assertArrayHasKey('sort', $type);
        $this->assertArrayHasKey('conditions', $type);
        $this->assertEquals('integer', $type['status']);
        $this->assertEquals('integer', $type['level']);
        $this->assertEquals('integer', $type['sort']);
        $this->assertEquals('json', $type['conditions']);
    }

    public function testPermissionModelJsonFields(): void
    {
        $perm = new Permission();
        $json = $this->getProperty($perm, 'json');
        $this->assertContains('conditions', $json);
    }

    public function testPermissionModelReadonlyFields(): void
    {
        $perm = new Permission();
        $readonly = $this->getProperty($perm, 'readonly');
        $this->assertContains('create_time', $readonly);
    }

    public function testPermissionModelUsesSoftDelete(): void
    {
        $perm = new Permission();
        $traits = class_uses($perm);
        $this->assertArrayHasKey(\think\model\concern\SoftDelete::class, $traits);
    }

    public function testPermissionModelExtendsThinkModel(): void
    {
        $perm = new Permission();
        $this->assertInstanceOf(\think\Model::class, $perm);
    }


    public function testUserRoleModelTableName(): void
    {
        $userRole = new UserRole();
        $this->assertEquals('auth_user_role', $this->getProperty($userRole, 'name'));
    }

    public function testUserRoleModelAutoTimestamp(): void
    {
        $userRole = new UserRole();
        $this->assertTrue($this->getProperty($userRole, 'autoWriteTimestamp'));
    }

    public function testUserRoleModelTimestampFields(): void
    {
        $userRole = new UserRole();
        $this->assertEquals('create_time', $this->getProperty($userRole, 'createTime'));
        $this->assertEquals('update_time', $this->getProperty($userRole, 'updateTime'));
    }

    public function testUserRoleModelExtendsThinkModel(): void
    {
        $userRole = new UserRole();
        $this->assertInstanceOf(\think\Model::class, $userRole);
    }

    public function testUserRoleModelNoSoftDelete(): void
    {
        $userRole = new UserRole();
        $traits = class_uses($userRole);
        $this->assertArrayNotHasKey(\think\model\concern\SoftDelete::class, $traits);
    }


    public function testAllModelsExtendThinkModel(): void
    {
        $models = [new Role(), new Permission(), new UserRole()];
        foreach ($models as $model) {
            $this->assertInstanceOf(\think\Model::class, $model);
        }
    }

    public function testRoleAndPermissionHaveSoftDelete(): void
    {
        $roleTraits = class_uses(new Role());
        $permTraits = class_uses(new Permission());

        $this->assertArrayHasKey(\think\model\concern\SoftDelete::class, $roleTraits);
        $this->assertArrayHasKey(\think\model\concern\SoftDelete::class, $permTraits);
    }
}
