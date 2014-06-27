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

        if (($key = array_search($accessRole, $this->cachedRolesList, true)) !== false) {
            unset($this->cachedRolesList[$key]);
            $this->cachedRolesList[$accessRole] = true;
            return $this->prepareAccessLevel($accessRole, true);
        }

        if (preg_match('~^([^\*\+\-]*)([\*\+\-]{1})(.*)$~', $accessRole, $matches)) {
            $head = $matches[1];
            $sign = $matches[2];
            $tail = $matches[3];
            if ('+' === $sign) {
                return $this->prepareAccessLevel(
                    $accessRole
                    , $this->checkAccessRole($head, $user, $prop) || $this->checkAccessRole($tail, $user, $prop)
                );
            }
            if ('-' === $sign) {
                return $this->prepareAccessLevel(
                    $accessRole
                    , $this->checkAccessRole($head, $user, $prop) && !$this->checkAccessRole($tail, $user, $prop)
                );
            }
            if ('*' === $sign) {
                return $this->prepareAccessLevel(
                    $accessRole
                    , $this->checkAccessRole($head, $user, $prop) && $this->checkAccessRole($tail, $user, $prop)
                );
            }
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

    private function checkAccessStrategy(&$accessStrategy, $user, $prop = array())
    {
        if (empty($accessStrategy) || !is_callable($accessStrategy)) {
            return $this->prepareAccessLevel($accessStrategy, false);
        }
        $accessStrategy = $accessStrategy($user, $prop);

        return $this->prepareAccessLevel($accessStrategy, $this->checkAccessLevel($accessStrategy, $user, $prop));

    }
}