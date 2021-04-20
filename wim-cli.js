const fs = require('fs-extra');
const path = require('path');
const fetch = require('node-fetch');
const inquirer = require('inquirer');
// const { buildDepTreeFromFiles } = require('snyk-nodejs-lockfile-parser');
const { PackageLockParser } = require('snyk-nodejs-lockfile-parser/dist/parsers/package-lock-parser');
const { Yarn2LockParser } = require('snyk-nodejs-lockfile-parser/dist/parsers/yarn2-lock-parser');
const { YarnLockParser } = require('snyk-nodejs-lockfile-parser/dist/parsers/yarn-lock-parser');
const { LockParserBase } = require('snyk-nodejs-lockfile-parser/dist/parsers/lock-parser-base');
const _ = require('lodash');
const throat = require('throat');
const d = require('@geeeger/deferred').default;

const { flattenPackageLockDeps } = require('flatten-package-lock-deps');

/**
 * @description getPath
 * @param {string} type
 * @return {string}  
 */
function getPackageLockPath(type) {
    return path.resolve(process.cwd(), type === 'npm' ? 'package-lock.json' : 'yarn.lock');
}

/**
 * @description getLockFileContent
 * @param {string} type
 * @return {string}  
 */
function getPackageLock(type) {
    return fs.readFileSync(getPackageLockPath(type));
}

let debugFlag = false;

inquirer
    .prompt([
        {
            name: 'type',
            type: 'list',
            message: '请选择你的lock文件类型',
            choices: ['npm', 'yarn', 'yarn2']
        },
        {
            name: 'debug',
            type: 'confirm',
            message: '是否开启debug'
        }
    ])
    .then(({ type, debug }) => {
        /** @type {LockParserBase} */
        let Parser;

        debugFlag = debug;

        switch (type) {
            case 'npm':
                Parser = PackageLockParser;
                break;
            case 'yarn':
                Parser = YarnLockParser;
                break;
            case 'yarn2':
                Parser = Yarn2LockParser;
                break;
        }

        if (!type) {
            throw new Error('未选择类型');
        }
        /** @type {PackageLockParser} */
        let parser = new Parser();

        let lockfile = parser.parseLockFile(getPackageLock(type));
        return flattenPackageLockDeps(lockfile, {
            ignoreDev: false
        });
    })
    .then(flattenDepMap => {
        let resolvedList = _.map(flattenDepMap, 'resolved');
        resolvedList = _.map(resolvedList, item => new URL(item).origin);

        const promise = inquirer.prompt({
            name: 'resolved',
            type: 'list',
            message: '请选择要检查的包来源',
            choices: _.uniq(resolvedList)
        }).then(res => {
            return Object.assign({}, {
                flattenDepMap
            }, res)
        });
        return promise;
    })
    .then(({ flattenDepMap, resolved }) => {
        let list = _.toArray(flattenDepMap);
        list = _.filter(list, item => item.resolved.startsWith(resolved));

        if (debugFlag) {
            console.log('筛选出的数据')
            console.log(_.map(list, item => {
                return {
                    n: item.name,
                    v: item.version,
                    r: item.resolved
                }
            }))
        }

        return list;
    })
    .then(list => {
        console.log('比对hash中');

        function getHash(item) {
            const promise = d()
            if (debugFlag) {
                console.log(`向npm源站请求包信息: ${item.name}@${item.version}`)
            }
            fetch(`https://registry.npmjs.org/${item.name}/${item.version}`)
                .then(res => {
                    return res.json();
                })
                .then(res => {
                    promise.resolve(Object.assign({}, item, {
                        dist: res.dist,
                        failed: false
                    }));
                })
                .catch(() => {
                    console.log(`请求npm失败: ${item.name}@${item.version}` );
                    promise.resolve(Object.assign({}, item, {
                        dist: null,
                        failed: true
                    }));
                });
            return promise.promise;
        }
        return Promise.all(
            list.map(throat(1, (item) => getHash(item)))
        )
    })
    .then(list => {
        list = _.filter(list, item => {
            if (!item.failed && (!item.dist || !item.dist.shasum) && debugFlag) {
                console.log(`${item.name}@${item.version} 无源包信息`)
            }
            return item.dist;
        });
        list = _.map(list, item => {
            if (item.depth === 0) {
                try {
                    item.local = require(`${item.name}/package.json`)._shasum;
                }
                catch (e) {
                    if (debugFlag) {
                        console.log(`${item.name}@${item.version}: 请求${item.name}/package.json失败`)
                    }
                }
            }
            else {
                let i;
                item.parents.forEach((parent, index) => {
                    if (fs.existsSync(`${parent}/node_modules/${item.name}`)) {
                        i = index;
                    }
                });

                if (i !== undefined) {
                    try {
                        item.local = require(`${item.parents[i]}/node_modules/${item.name}/package.json`)._shasum;
                    }
                    catch (e) {
                        if (debugFlag) {
                            console.log(`${item.name}@${item.version}: 请求${item.parents[i]}/node_modules/${item.name}/package.json失败`)
                        }
                    }
                } else {
                    if (debugFlag) {
                        console.log(`${item.name}@${item.version}: 深度1未找到该包,跳过`)
                    }
                }
            }
            return item
        })
        list = _.filter(list, item => item.local)

        list = _.map(list, item => {
            item.equal = item.local === item.dist.shasum;
            return item;
        })

        console.log('结果')

        console.log(_.filter(list, item => !item.equal))
    })



// const parser = new PackageLockParser()

// const json = parser.parseLockFile(fs.readFileSync(getPackageLockPath(), 'utf-8'))

// parser.getDepMap()