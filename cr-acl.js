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
             * Get roles from where roleName inherits
             */
            crAcl.getInheritanceRole = function (roleName) {
                return self.roles[roleName];
            }

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
                var isGranted = crAcl.recursiveRoleCheck(crAcl.getRole(), is_allowed);
                return isGranted;
            };

            crAcl.recursiveRoleCheck = function(userRole, allowedRoles) {
                console.info('-----')
                console.log(userRole)
                console.log(allowedRoles);

                if ((userRole in self.roles) === false) {
                    throw "This role[" + userRole + "] does not exist into InheritanceRoles declaration";
                }

                if (allowedRoles.indexOf(userRole) != -1) {
                    return true;
                }

                if (allowedRoles.indexOf("ROLE_GUEST") != -1) {
                    return true;
                }

                var roles = crAcl.getInheritanceRole(userRole);
                for (var i in roles){
                    if (roles[i] != 'ROLE_USER' && roles[i] != 'ROLE_GUEST' && crAcl.recursiveRoleCheck(roles[i], allowedRoles)) {
                       return true;
                    }
                }

                return false;
            }

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
}]).directive("crGranted", ['crAcl', function(acl) {
    return {
        restrict: "A",
        replace: false,
        link: function(scope, elem, attr, ctrl, $transclude) {
            scope.$watch(function() {
                return acl.getRole();
            }, function(newV, oldV) {

                var allowedRoles = attr.crGranted.split(",");
                var userRole = acl.getRole();
                var hasRole = acl.recursiveRoleCheck(userRole, allowedRoles);

                if (!hasRole) {
                    elem.remove();
                }
            });
        }
    };
}]);
