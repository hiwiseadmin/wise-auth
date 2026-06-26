<?php
/**
 * 约束违反异常
 *
 * 当 RBAC2 约束检查失败时抛出。
 */
namespace wise\auth\exception;

use think\Exception;

class ConstraintViolationException extends Exception
{
    /**
     * @var string 约束类型
     */
    protected $constraintType = '';

    /**
     * ConstraintViolationException constructor.
     *
     * @param string $message        错误消息
     * @param string $constraintType 约束类型（如 mutual_exclusion, cardinality, prerequisite）
     * @param int    $code           错误码
     */
    public function __construct(string $message = '', string $constraintType = '', int $code = 0)
    {
        parent::__construct($message, $code);
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
