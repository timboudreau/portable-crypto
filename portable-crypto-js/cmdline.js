/*
 The MIT License (MIT)
 
 Copyright (c) 2014 Tim Boudreau
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
const path = require('path');
function preprocessArgs(args) {
    var result = [];
    args.forEach(function (arg) {
        var shortPattern = /^\-(\w\w*)$/
        if (shortPattern.test(arg)) {
            for (var i = 0; i < arg.length; i++) {
                if (arg[i] !== '-') {
                    result.push('-' + arg[i])
                }
            }
        } else {
            result.push(arg)
        }
    })
    return result;
}

/**
 * General purpose argument processing.
 * If you want to handle both short (-f) and long (--file) variants,
 * pass in a map of expansions, e.g. { f : 'file' } and they
 * will be handled automagically.
 *
 * Returns null if there are no arguments
 *
 * Returns a hash of arguments, minus the - characters,
 * such that any set argument which starts
 * with a dash and is followed by another argument with a dash will get
 * a value of true - i.e. "--foo --bar"  gets you { foo : true, bar : true }
 * while following a switch with something that doesn't start with a -
 * assigns that value in the hash - i.e. "--file /tmp/quux --bar" gets you
 * { file : '/tmp/quux', bar : true }.
 */
function parseArgs() {
    var expansions = {};
    var processArgs = null;
    for (var i = 0; i < arguments.length; i++) {
        if (typeof arguments[i] === 'undefined') {
            continue;
        }
        if (Array.isArray(arguments[i])) {
            processArgs = arguments[i]
        } else if (typeof arguments[i] === 'object') {
            expansions = arguments[i]
        }
    }
    var result = {};
    var args = processArgs || process.argv.slice(2);
    if (!args || args.length === 0) {
        return {};
    }
    //expend, e.g. -pvq to -p -v -q
    args = preprocessArgs(args);
    var previous;
    for (var i = 0; i < args.length; i++) {
        var arg = args[i]
        var shortPattern = /^\-(\w)$/
        if (shortPattern.test(arg)) {
            var letter = shortPattern.exec(arg)[1]
            if (expansions && shortPattern.test(arg)) {
                if (typeof expansions[letter] !== 'undefined') {
                    arg = '--' + expansions[letter]
                    previous = expansions[letter]
                } else {
                    result[letter] = true
                    previous = letter
                    continue
                }
            } else {
                result[letter] = true
                previous = letter
                continue
            }
        }
        //we've now substituted in, e.g. --foo for -foo'
        var optPattern = /^\-\-(\w.*?)$/;
        if (optPattern.test(arg)) {
            var name = optPattern.exec(arg)[1];
            result[name] = true;
            previous = name;
            continue;
        }
        if (previous) {
            result[previous] = arg;
            previous = null;
        } else {
            result[arg] = true;
        }
    }
    return result;
}

function keys(hash) {
    if (Array.isArray(hash)) {
        var result = [];
        for (var i = 0; i < hash.length; i++) {
            result.push(i);
        }
    } else {
        return Object.keys(hash);
    }
}

function undot(hash) {
    if (typeof hash === 'string' || typeof hash === 'boolean' || typeof hash === 'number') {
        return hash;
    }
    var result = {};
    var ks = keys(hash);
    for (var i = 0; i < ks.length; i++) {
        var key = ks[i];
        var found = undotOne(key, hash[key]);
        if (typeof found === 'object') {
            result = {...result, ...found};
        } else {
            result[key] = found;
        }
    }
    return result;
}

function typify(obj) {
    if (typeof obj === 'string') {
        if (/^\d+$/.test(obj)) {
            return parseInt(obj);
        } else if ('true' === obj) {
            return true;
        } else if ('false' === obj) {
            return false;
        }
        return obj;
    } else {
        return obj;
    }
}

function undotOne(key, val) {
    var parts = key.split(/\.(.+)/);
    var result = {};
    if (parts.length > 1) {
        result[parts[0]] = undotOne(parts[1], val);
        return result;
    }
    result[key] = typify(val);
    return result;
}

module.exports.parseArgs = parseArgs;
