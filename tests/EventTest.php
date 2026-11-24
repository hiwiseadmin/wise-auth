<?php
/**
 * 事件类单元测试
 *
 * 测试 RoleChanged 和 PermissionChanged 事件类。
 */
namespace wise\auth\tests;

use wise\auth\event\RoleChanged;
use wise\auth\event\PermissionChanged;

class EventTest extends TestCase
{

    public function testRoleChangedCreateEvent(): void
    {
        $event = new RoleChanged('create', 1, ['name' => 'Admin']);
        $this->assertEquals('create', $event->action);
        $this->assertEquals(1, $event->roleId);
        $this->assertEquals(['name' => 'Admin'], $event->data);
    }

    public function testRoleChangedUpdateEvent(): void
    {
        $event = new RoleChanged('update', 5, ['name' => 'Editor', 'status' => 1]);
        $this->assertEquals('update', $event->action);
        $this->assertEquals(5, $event->roleId);
        $this->assertEquals(['name' => 'Editor', 'status' => 1], $event->data);
    }

    public function testRoleChangedDeleteEvent(): void
    {
        $event = new RoleChanged('delete', 10);
        $this->assertEquals('delete', $event->action);
        $this->assertEquals(10, $event->roleId);
        $this->assertEquals([], $event->data);
    }

    public function testRoleChangedEmptyData(): void
    {
        $event = new RoleChanged('create', 1);
        $this->assertEquals([], $event->data);
    }

    public function testRoleChangedDataWithSlug(): void
    {
        $data = ['name' => 'Super Admin', 'slug' => 'super_admin', 'parent_id' => 0];
        $event = new RoleChanged('create', 1, $data);
        $this->assertEquals('super_admin', $event->data['slug']);
        $this->assertEquals(0, $event->data['parent_id']);
    }

    public function testRoleChangedActionIsCreate(): void
    {
        $event = new RoleChanged('create', 1);
        $this->assertEquals('create', $event->action);
    }

    public function testRoleChangedActionIsString(): void
    {
        $event = new RoleChanged('create', 1);
        $this->assertIsString($event->action);
    }

    public function testRoleChangedRoleIdIsInt(): void
    {
        $event = new RoleChanged('create', 42);
        $this->assertIsInt($event->roleId);
        $this->assertEquals(42, $event->roleId);
    }

    public function testRoleChangedDataIsArray(): void
    {
        $event = new RoleChanged('create', 1);
        $this->assertIsArray($event->data);
    }


    public function testPermissionChangedCreateEvent(): void
    {
        $event = new PermissionChanged('create', 1, ['ident' => 'admin.user.list']);
        $this->assertEquals('create', $event->action);
        $this->assertEquals(1, $event->permissionId);
        $this->assertEquals(['ident' => 'admin.user.list'], $event->data);
    }

    public function testPermissionChangedUpdateEvent(): void
    {
        $event = new PermissionChanged('update', 3, ['ident' => 'admin.user.edit', 'name' => 'Edit User']);
        $this->assertEquals('update', $event->action);
        $this->assertEquals(3, $event->permissionId);
        $this->assertEquals('admin.user.edit', $event->data['ident']);
        $this->assertEquals('Edit User', $event->data['name']);
    }

    public function testPermissionChangedDeleteEvent(): void
    {
        $event = new PermissionChanged('delete', 7);
        $this->assertEquals('delete', $event->action);
        $this->assertEquals(7, $event->permissionId);
        $this->assertEquals([], $event->data);
    }

    public function testPermissionChangedEmptyData(): void
    {
        $event = new PermissionChanged('create', 1);
        $this->assertEquals([], $event->data);
    }

    public function testPermissionChangedFullData(): void
    {
        $data = [
            'ident' => 'admin.dashboard',
            'name' => 'Dashboard',
            'type' => 'route',
            'route' => '/admin/index/index',
            'method' => '*',
        ];
        $event = new PermissionChanged('create', 1, $data);
        $this->assertEquals('route', $event->data['type']);
        $this->assertEquals('/admin/index/index', $event->data['route']);
        $this->assertEquals('*', $event->data['method']);
    }

    public function testPermissionChangedActionIsCreate(): void
    {
        $event = new PermissionChanged('create', 1);
        $this->assertEquals('create', $event->action);
    }

    public function testPermissionChangedActionIsString(): void
    {
        $event = new PermissionChanged('update', 1);
        $this->assertIsString($event->action);
    }

    public function testPermissionChangedPermissionIdIsInt(): void
    {
        $event = new PermissionChanged('create', 99);
        $this->assertIsInt($event->permissionId);
        $this->assertEquals(99, $event->permissionId);
    }

    public function testPermissionChangedDataIsArray(): void
    {
        $event = new PermissionChanged('create', 1);
        $this->assertIsArray($event->data);
    }


    public function testBothEventsForSameAction(): void
    {
        $roleEvent = new RoleChanged('create', 1);
        $permEvent = new PermissionChanged('create', 1);

        $this->assertEquals($roleEvent->action, $permEvent->action);
    }

    public function testAllActionsSupported(): void
    {
        $actions = ['create', 'update', 'delete'];
        foreach ($actions as $action) {
            $roleEvent = new RoleChanged($action, 1);
            $this->assertEquals($action, $roleEvent->action);

            $permEvent = new PermissionChanged($action, 1);
            $this->assertEquals($action, $permEvent->action);
        }
    }
}
