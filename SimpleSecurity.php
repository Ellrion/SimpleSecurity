<?php namespace Ellrion\SimpleSecurity;

class SecurityService
{
    private $rolesList;
    private $currentUser;
    private $cachedRolesList;

    public function __construct($rolesList, $currentUser = null)
    {
        $this->rolesList = $rolesList;
        $this->currentUser = $currentUser;
        $this->flushRolesCache();
    }

    public function isGranted($security, $user = null)
    {
        if (is_null($user)) {
            $accessLevel = $security;
            return $this->checkAccessLevel($accessLevel, $this->currentUser);
        } else {
            $accessLevel = $security;
            $this->flushRolesCache();
            $access = $this->checkAccessLevel($accessLevel, $user);
            $this->flushRolesCache();
            return $access;
        }
    }

    public function addToRolesList($list)
    {
        $this->rolesList = array_merge($this->rolesList, $list);
        $this->flushRolesCache();
    }

    public function getRolesList()
    {
        return $this->cachedRolesList;
    }

    public function flushRolesCache()
    {
        $this->cachedRolesList = $this->rolesList;
    }

    private function checkAccessLevel(&$accessLevel, $user, $prop = array())
    {
        if (empty($accessLevel)) {
            return $this->prepareAccessLevel($accessLevel, false);
        }
        if (is_bool($accessLevel)) {
            return $accessLevel;
        }
        if (is_array($accessLevel)) {
            return $this->prepareAccessLevel($accessLevel, $this->checkAccessRule($accessLevel, $user, $prop));
        }
        if (is_string($accessLevel)) {
            return $this->prepareAccessLevel($accessLevel, $this->checkAccessRole($accessLevel, $user, $prop));
        }
        if (is_callable($accessLevel)) {
            return $this->prepareAccessLevel($accessLevel, $this->checkAccessStrategy($accessLevel, $user, $prop));
        }

        return $this->prepareAccessLevel($accessLevel, true);
    }

    private function prepareAccessLevel(&$accessLevel, $value)
    {
        return $accessLevel = !empty($value);
    }

    private function checkAccessRule(&$accessRule, $user, $prop = array())
    {
        if (empty($accessRule) || !is_array($accessRule)) {
            return $this->prepareAccessLevel($accessRule, false);
        }

        return $this->prepareAccessLevel(
            $accessRule
            , (
                (!isset($accessRule['parent']) || $this->checkAccessLevel($accessRule['parent'], $user, $prop))
                && (!isset($accessRule['allow']) || $this->checkAccessLevel($accessRule['allow'], $user, $prop))
                && (!isset($accessRule['deny']) || !$this->checkAccessLevel($accessRule['deny'], $user, $prop))
            )
        );
    }

    private function checkAccessStrategy(&$accessStrategy, $user, $prop = array())
    {
        if (empty($accessStrategy) || !is_callable($accessStrategy)) {
            return $this->prepareAccessLevel($accessStrategy, false);
        }
        $accessStrategy = $accessStrategy($user, $prop);

        return $this->prepareAccessLevel($accessStrategy, $this->checkAccessLevel($accessStrategy, $user, $prop));

    }

    private function checkAccessRole(&$accessRole, $user, $prop = array())
    {
        if (empty($accessRole) || !is_string($accessRole)) {
            return $this->prepareAccessLevel($accessRole, false);
        }

        if (isset($this->cachedRolesList[$accessRole])) {
            return $this->prepareAccessLevel(
                $accessRole
                , $this->checkAccessLevel($this->cachedRolesList[$accessRole], $user, $prop)
            );
        }

        if (($key = array_search($accessRole, $this->cachedRolesList, true)) !== false && is_int($key)) {
            unset($this->cachedRolesList[$key]);
            $this->cachedRolesList[$accessRole] = true;
            return $this->prepareAccessLevel($accessRole, true);
        }

        if (strpbrk($accessRole, '+-*')) {
            return $this->prepareAccessLevel($accessRole, $this->checkAccessRoleExpr($accessRole, $user, $prop));
        }

        if (strpos($accessRole, ':')) {
            $role_parts = explode(':', $accessRole, 2);
            if (!isset($this->cachedRolesList[$role_parts[0].':'])) {
                return $this->prepareAccessLevel($accessRole, false);
            }
            $this->cachedRolesList[$accessRole] = $this->cachedRolesList[$role_parts[0].':'];
            $prop = array_merge($prop, array($role_parts[0]=>$role_parts[1]));
            return $this->prepareAccessLevel(
                $accessRole
                , $this->checkAccessLevel($this->cachedRolesList[$accessRole], $user, $prop)
            );
        }


        return $this->prepareAccessLevel($accessRole, false);
    }

    private function checkAccessRoleExpr(&$accessRole, $user, $prop = array())
    {
        $expr = $this->prepareAccessRoleExpr($accessRole);
        $stack = array();
        while ($token = array_shift($expr)) {
            if (in_array($token, ['*', '+', '-'])) {
                if (count($stack) < 2) {
                    return $this->prepareAccessLevel($accessRole, false);
                }
                $b = array_pop($stack);
                $a = array_pop($stack);
                switch ($token) {
                    case '*':
                        $res = $a && $b;
                        break;
                    case '+':
                        $res = $a || $b;
                        break;
                    case '-':
                        $res = $a && !$b;
                        break;
                }
                array_push($stack, $res);
            } else {
                array_push($stack, $this->checkAccessRole($token, $user, $prop));
            }
        }
        if (count($stack) > 1) {
            return $this->prepareAccessLevel($accessRole, false);
        }

        return $this->prepareAccessLevel($accessRole, array_pop($stack));
    }

    protected function prepareAccessRoleExpr($accessRoleExpr) {
        $expr = array_map(
            'trim'
            , preg_split('/([\+\-\*\(\)])|\s+/', $accessRoleExpr, null, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE)
        );

        $precedence = [
            '(' => 0,
            ')' => 0,
            '-' => 3,
            '+' => 3,
            '*' => 6
        ];

        $final_stack = [];
        $operator_stack = [];

        while ($token = array_shift($expr)) {
            if (in_array($token, ['*', '+', '-'])) {
                $top = end($operator_stack);
                if ($top && $precedence[$token] <= $precedence[$top]) {
                    $operator = array_pop($operator_stack);
                    array_push($final_stack, $operator);
                }
                array_push($operator_stack, $token);
            } elseif ('(' === $token) {
                array_push($operator_stack, $token);
            } elseif (')' === $token) {
                do {
                    $operator = array_pop($operator_stack);
                    if ($operator == '(') {
                        break;
                    }
                    array_push($final_stack, $operator);
                } while ($operator);
            } else {
                array_push($final_stack, $token);
            }
        }
        while ($operator = array_pop($operator_stack)) {
            array_push($final_stack, $operator);
        }

        return $final_stack;
    }
}