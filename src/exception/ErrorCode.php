<?php
declare(strict_types=1);

namespace wise\auth\exception;

use wise\support\exception\ErrorCodeInterface;

/**
 * wise-auth 业务错误码（号段 30000~39999）
 *
 * 号段分配约定（见 wise-support\exception\WiseException 号段全景）：
 *  30000~30099  权限/授权
 *  30100~30199  RBAC 约束
 *
 * @package wise\auth\exception
 */
enum ErrorCode: int implements ErrorCodeInterface
{
    /** 未授权访问（无权限） */
    case UNAUTHORIZED         = 30000;

    /** RBAC 约束违反 */
    case CONSTRAINT_VIOLATION = 30100;

    /**
     * 错误码对应的默认中文说明
     */
    public function defaultMessage(): string
    {
        return match ($this) {
            self::UNAUTHORIZED         => '未授权访问',
            self::CONSTRAINT_VIOLATION => '约束条件不满足',
        };
    }
}
