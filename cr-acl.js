angular.module("cr.acl", ['ngCookies']).constant("cr-acl.config", {
    "redirect": "unauthorized",
    "roles": {
        "ROLE_USER": ["ROLE_USER"],
        "ROLE_GUEST": ["ROLE_GUEST"]
    }
}).provider("crAcl", ['cr-acl.config', function(config) {
    var self = {};
    self.roles = config.roles;
    self.redirect = config.redirect;
    /**
     * Your role is granted for this route?
     * @param string identityRole
     * @param array  sstateRolesGranted
     * @return bool
     */
    self.isGranted = function(identityRole, stateRolesGranted) {
        var granted = false;
        if ((identityRole in self.roles) === false) {
            throw "This role[" + identityRole + "] not exist into InheritanceRoles declaration";
        }
        if (stateRolesGranted.indexOf(identityRole) !== -1) {
            granted = true;
        }
        for (var ii in self.roles[identityRole]) {
            if (stateRolesGranted.indexOf(self.roles[identityRole][ii]) !== -1) {
                granted = true;
            }
        }
        return granted;
    };
    this.$get = ['$q', '$rootScope', '$injector', '$cookies', '$state',
        function($q, $rootScope, $injector, $cookies, $state) {
            var crAcl = {};
            /**
             * Configure roles tree
             * @param arrat roles
             */
            crAcl.setInheritanceRoles = function(roles) {
                angular.forEach(roles, function(inheritance, roleName) {
                    if (roleName == "ROLE_USER" && roleName == "ROLE_GUEST") {
                        throw roleName + " is a reserved world because is a father of ROLE, you can not override it";
                    }
                    self.roles[roleName] = inheritance;
                });
            };
            /**
             * Set route name for redirect after unauthorized operation
             */
            crAcl.setRedirect = function(redirectStateName) {
                self.redirect = redirectStateName;
            };
            /**
             * Unset Role
             * @param string role
             */
            crAcl.unsetRole = function(role) {
                $cookies.remove('identityRole');
            };
            /**
             * Set Role
             * @param string role
             */
            crAcl.setRole = function(role) {
                $cookies.put('identityRole', role);
            };
            /**
             * Get Redirect From Params
             * @param string role
             */
            crAcl.getFromParams = function(role) {
                var from = $cookies.getObject('fromParams');
                return from;
            };
            /**
             * Get Redirect From State
             * @param string role
             */
            crAcl.getFromState = function(role) {
                return $cookies.getObject('fromState');
            };
            crAcl.resetFromState = function(role) {
                $cookies.remove('fromState');
                $cookies.remove('fromParams');
            };
            /**
             * Return your role
             * @return string
             */
            crAcl.getRole = function() {
                if ($cookies.get('identityRole') === undefined) {
                    return "ROLE_GUEST";
                }
                return $cookies.get('identityRole');
            };
            var afterChangeStart = function(event, toState, toParams, fromState, fromParams) {
                if (!toState.data || !toState.data.is_granted) {
                    return crAcl;
                }
                if (toState.data.is_granted[0] === "*") {
                    return crAcl;
                }
                var is_allowed = (toState.data.is_granted !== undefined) ? toState.data.is_granted : ["ROLE_GUEST"];
                var isGranted = self.isGranted(crAcl.getRole(), is_allowed);
                return isGranted;
            };
            /**
             *  getNestedStateUrl
             */
            $rootScope.getNestedStateUrl = function(state) {
                var url = state.url;
                if (state.parent) {
                    var parentState = $state.get(state.parent);
                    url = $rootScope.getNestedStateUrl(parentState) + url;
                }
                return url;
            }
            $rootScope.$on('$stateChangeStart', function(event, toState, toParams, fromState, fromParams) {
                $injector.invoke(
                    ["$state", "$location", "$urlMatcherFactory",
                        function($state, $location, $urlMatcherFactory) {
                            var isGranted = afterChangeStart(event, toState, toParams, fromState, fromParams);
                            var search = $location.search();
                            var path = $location.path();
                            var stateParams;
                            if (!isGranted && self.redirect !== false) {
                                event.preventDefault();
                                if ($location.path() == "/" && !$location.search()) {
                                    crAcl.resetFromState();
                                } else {
                                    angular.forEach($state.get(), function(state) {
                                        var nestedStateUrl = $rootScope.getNestedStateUrl(state);
                                        var urlMatcher = $urlMatcherFactory.compile(nestedStateUrl);
                                        if (stateParams = urlMatcher.exec(path, search)) {
                                            $cookies.putObject('fromState', state);
                                            $cookies.putObject('fromParams', stateParams);
                                        }
                                    })
                                }
                                if (self.redirect != toState.name) {
                                    $state.go(self.redirect);
                                }
                            }
                        }
                    ]);
            });
            return crAcl;
        }
    ];
}]).directive("crGranted", ['crAcl', '$animate', function(acl, $animate) {
    console.info(acl.getRole())
    return {
        restrict: "A",
        replace: false,
        transclude: 'element',
        terminal: true,
        link: function(scope, elem, attr, ctrl, $transclude) {
            var content = false;
            $transclude(function(clone, newScope) {
                childScope = newScope;
                clone[clone.length++] = document.createComment(' end crGranted: ' + attr.crGranted + ' ');
                block = {
                    clone: clone
                };
                content = clone;
            });
            scope.$watch(function() {
                return acl.getRole();
            }, function(newV, oldV) {
                console.log(attr.crGranted);
                var allowedRoles = attr.crGranted.split(",");

                /**
                 * NEED FIX!!! Should be chaking FULL hierarchy, and not just first level.
                 */

                if (allowedRoles.indexOf(acl.getRole()) != -1) {
                    $animate.enter(content, elem.parent(), elem);
                } else {
                    if (content) {
                        content.remove();
                    }
                }
            });
        }
    };
}]);