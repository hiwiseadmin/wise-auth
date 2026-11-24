<?php
/**
 * 约束违反异常
 *
 * 当 RBAC2 约束检查失败时抛出。
 */
declare(strict_types=1);

namespace wise\auth\exception;

use wise\support\exception\WiseException;

class ConstraintViolationException extends WiseException
{
    /**
     * @var string 约束类型
     */
    protected string $constraintType = '';

    /**
     * ConstraintViolationException constructor.
     *
     * @param string $message        错误消息
     * @param string $constraintType 约束类型（如 mutual_exclusion, cardinality, prerequisite）
     * @param int    $code           业务错误码（默认 ErrorCode::CONSTRAINT_VIOLATION）
     */
    public function __construct(string $message = '', string $constraintType = '', int $code = ErrorCode::CONSTRAINT_VIOLATION->value)
    {
        parent::__construct($code, $message, 409);
        $this->constraintType = $constraintType;
    }

    /**
     * 获取约束类型
     *
     * @return string
     */
    public function getConstraintType(): string
    {
        return $this->constraintType;
    }
}
