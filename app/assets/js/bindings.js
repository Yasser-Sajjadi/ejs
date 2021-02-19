/* Two-Way binding with jQuery */

(function($) {
    isObject = (value) => {
        return (typeof value === "object") && (value !== null) && (value !== undefined);
    }

    $.fn.bindings = (data) => {

        const inps = ['textarea', 'input', 'select'];

        var onchange = (cs, action, index, value) => {
            console.info({ id: $(cs.content).attr('id'), cs, action });
            if (typeof cs.value === "object") {
                watch(cs.content, cs, cs.value);
            } else {
                $(`[data-bind="${cs.property}"]`).each((index, element) => {
                    if ($(element).attr('data-bind') === cs.property) {
                        element.value = cs.value;
                        element.textContent = cs.value;
                    }
                });
            }
        }

        var prepare = (element, cs, object, property) => {
            if (!cs.hasOwnProperty(property)) {
                Object.defineProperty(cs, property, {
                    configurable: true,
                    enumerable: true,
                    value: {}
                });
                element.addEventListener('input', function() {
                    object[property] = element.value;
                });
            } else {
                element.addEventListener('input', function() {
                    object[property] = element.value;
                });
                return;
            }

            if ($.isArray(object[property])) {
                Object.defineProperty(object[property], "push", {
                    configurable: true,
                    enumerable: true,
                    value: function() {
                        for (var i = 0, n = this.length, l = arguments.length; i < l; i++, n++) {
                            cs[property].onchange(cs[property], "add", n, this[n] = arguments[i]);
                        }
                        return n;
                    }
                });

                Object.defineProperty(object[property], "pop", {
                    configurable: true,
                    enumerable: true,
                    value: function() {
                        if (this.length > -1) {
                            var n = this.length - 1,
                                item = this.pop();
                            delete this[n];
                            cs[property].onchange(cs[property], "remove", n, item);
                            return item;
                        }
                    }
                });

                Object.defineProperty(object[property], "unshift", {
                    configurable: true,
                    enumerable: true,
                    value: function() {
                        for (var i = 0, ln = arguments.length; i < ln; i++) {
                            this.splice(i, 0, arguments[i]);
                            defineIndexProperty(this.length - 1);
                            cs[property].onchange(cs[property], "add", i, arguments[i]);
                        }
                        for (; i < this.length; i++) {
                            cs[property].onchange(cs[property], "set", i, this[i]);
                        }
                        return this.length;
                    }
                });

                Object.defineProperty(object[property], "shift", {
                    configurable: true,
                    enumerable: true,
                    value: function() {
                        if (this.length > -1) {
                            var item = this.shift();
                            delete this[this.length];
                            cs[property].onchange(cs[property], "remove", 0, item);
                            return item;
                        }
                    }
                });

                Object.defineProperty(object[property], "splice", {
                    configurable: true,
                    enumerable: true,
                    value: function(index, howMany /*, element1, element2, ... */ ) {
                        var removed = [],
                            item;

                        index = index == null ? 0 : index < 0 ? this.length + index : index;

                        howMany = howMany == null ? this.length - index : howMany > 0 ? howMany : 0;

                        while (howMany--) {
                            item = this.splice(index, 1)[0];
                            removed.push(item);
                            delete this[this.length];
                            cs[property].onchange(cs[property], "remove", index + removed.length - 1, item);
                        }

                        for (var i = 2, ln = arguments.length; i < ln; i++) {
                            this.splice(index, 0, arguments[i]);
                            defineIndexProperty(this.length - 1);
                            cs[property].onchange(cs[property], "add", index, arguments[i]);
                            index++;
                        }

                        return removed;
                    }
                });
            }

            //console.info({ cs, property, value })

            Object.defineProperty(cs[property], 'onchange', {
                configurable: true,
                enumerable: true,
                value: onchange
            });

            Object.defineProperty(cs[property], 'property', {
                configurable: true,
                enumerable: true,
                value: property
            });

            Object.defineProperty(cs[property], 'content', {
                configurable: true,
                enumerable: true,
                get: function() {
                    return value;
                },
                set: function(val) {
                    value = val;
                    cs[property].onchange(cs[property], "content");
                }
            });

            //cs[property]['content'] = element;

            Object.defineProperty(cs[property], 'value', {
                configurable: true,
                enumerable: true,
                get: function() {
                    return value;
                },
                set: function(val) {
                    value = val;
                    cs[property].onchange(cs[property], "value");
                }
            });

            //cs[property]['value'] = object[property];

            Object.defineProperty(object, property, {
                configurable: true,
                enumerable: true,
                get: function() {
                    return value;
                },
                set: function(val) {
                    value = cs[property]['value'] = val;
                }
            });


        }

        var watch = (element, cs, object) => {
            $(element).each((i, e) => {
                let property = $(e).attr('data-bind');
                if (object.hasOwnProperty(property)) {
                    prepare(e, cs, object, property);
                }
            });
        }

        var config = (cs, object) => {
            cs = {
                data: object
            };
            watch($(`[data-bind]`), cs, object)
        }

        var construct = {};

        config(construct, data);

        return this;
    }

}(jQuery));