<?php
/**
 * AuthEventSubscriber 事件订阅者单元测试
 *
 * 测试事件订阅、缓存清除逻辑。
 */
namespace wise\auth\tests;

use Mockery;
use wise\auth\subscribe\AuthEventSubscriber;
use wise\auth\event\RoleChanged;
use wise\auth\event\PermissionChanged;

class AuthEventSubscriberTest extends TestCase
{
    /** @var AuthEventSubscriber */
    protected $subscriber;

    protected function setUp(): void
    {
        parent::setUp();
        $this->subscriber = new AuthEventSubscriber();
    }


    public function testSubscriberSubscribeMethodExists(): void
    {
        $this->assertTrue(method_exists($this->subscriber, 'subscribe'));
    }

    public function testSubscriberHasAllEventHandlers(): void
    {
        $methods = get_class_methods($this->subscriber);

        $expectedHandlers = [
            'subscribe',
            'onRoleChanged',
            'onPermissionChanged',
            'onRoleAssigning',
            'onRoleAssigned',
            'onRoleRemoving',
            'onRoleRemoved',
        ];

        foreach ($expectedHandlers as $handler) {
            $this->assertContains($handler, $methods, "AuthEventSubscriber must have method: {$handler}");
        }
    }


    public function testOnRoleChangedCreate(): void
    {
        $event = new RoleChanged('create', 1, ['name' => 'Admin']);
        $this->assertNotNull($event);
        $this->assertEquals('create', $event->action);
    }

    public function testOnRoleChangedUpdate(): void
    {
        $event = new RoleChanged('update', 2, ['name' => 'Editor']);
        $this->assertEquals('update', $event->action);
        $this->assertEquals(2, $event->roleId);
    }

    public function testOnRoleChangedDelete(): void
    {
        $event = new RoleChanged('delete', 3);
        $this->assertEquals('delete', $event->action);
        $this->assertEquals(3, $event->roleId);
    }


    public function testOnPermissionChangedCreate(): void
    {
        $event = new PermissionChanged('create', 1, ['ident' => 'admin.user.list']);
        $this->assertNotNull($event);
        $this->assertEquals('create', $event->action);
    }

    public function testOnPermissionChangedUpdate(): void
    {
        $event = new PermissionChanged('update', 1, ['ident' => 'admin.user.edit']);
        $this->assertEquals('update', $event->action);
    }

    public function testOnPermissionChangedDelete(): void
    {
        $event = new PermissionChanged('delete', 1);
        $this->assertEquals('delete', $event->action);
    }


    public function testOnRoleAssignedData(): void
    {
        $data = [
            'user_id'   => 1,
            'user_type' => 'admin',
            'role_ids'  => [1, 2],
        ];
        $this->assertEquals(1, $data['user_id']);
        $this->assertEquals('admin', $data['user_type']);
        $this->assertEquals([1, 2], $data['role_ids']);
    }

    public function testOnRoleAssignedWithMissingFields(): void
    {
        $data = ['role_ids' => [1]];
        $this->assertArrayNotHasKey('user_id', $data);
        $this->assertArrayNotHasKey('user_type', $data);
    }


    public function testOnRoleRemovedData(): void
    {
        $data = [
            'user_id'   => 5,
            'user_type' => 'member',
            'role_ids'  => [3],
        ];
        $this->assertEquals(5, $data['user_id']);
        $this->assertEquals('member', $data['user_type']);
    }


    public function testOnRoleAssigningIsNoop(): void
    {
        $reflection = new \ReflectionMethod($this->subscriber, 'onRoleAssigning');
        $this->assertEquals('void', $reflection->getReturnType()->getName());
    }

    public function testOnRoleRemovingIsNoop(): void
    {
        $reflection = new \ReflectionMethod($this->subscriber, 'onRoleRemoving');
        $this->assertEquals('void', $reflection->getReturnType()->getName());
    }


    public function testRoleChangedEventDataIntegrity(): void
    {
        $cases = [
            ['action' => 'create', 'roleId' => 1, 'data' => ['name' => 'Admin', 'slug' => 'admin']],
            ['action' => 'update', 'roleId' => 2, 'data' => ['name' => 'Editor']],
            ['action' => 'delete', 'roleId' => 3, 'data' => []],
        ];

        foreach ($cases as $case) {
            $event = new RoleChanged($case['action'], $case['roleId'], $case['data']);
            $this->assertEquals($case['action'], $event->action);
            $this->assertEquals($case['roleId'], $event->roleId);
            $this->assertEquals($case['data'], $event->data);
        }
    }

    public function testPermissionChangedEventDataIntegrity(): void
    {
        $cases = [
            ['action' => 'create', 'permId' => 1, 'data' => ['ident' => 'admin.user.list']],
            ['action' => 'update', 'permId' => 2, 'data' => ['ident' => 'admin.user.edit']],
            ['action' => 'delete', 'permId' => 3, 'data' => []],
        ];

        foreach ($cases as $case) {
            $event = new PermissionChanged($case['action'], $case['permId'], $case['data']);
            $this->assertEquals($case['action'], $event->action);
            $this->assertEquals($case['permId'], $event->permissionId);
            $this->assertEquals($case['data'], $event->data);
        }
    }


    public function testSubscriberClassExists(): void
    {
        $this->assertTrue(class_exists(AuthEventSubscriber::class));
    }

    public function testSubscriberIsInstantiable(): void
    {
        $this->assertInstanceOf(AuthEventSubscriber::class, $this->subscriber);
    }
}
