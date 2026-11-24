<?php

declare(strict_types=1);

namespace wise\auth\tests\fixtures;

/**
 * 无任何权限 Attribute 的控制器（扫描应返回空数组）
 */
class PlainController
{
    public function index(): void
    {
    }
}
