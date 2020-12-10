'use strict';
const joi = require('joi').extend(require('joi-extension-semver'));
const fs = require('fs');
const recursive = require("recursive-readdir");


const vulnPaths = require('../../index').paths;

const npmModel = joi.object().keys({
    id: joi.number().required(),
    created_at: joi.string().regex(/^\d{4}-\d{2}-\d{2}$/).required().isoDate(),
    updated_at: joi.string().regex(/^\d{4}-\d{2}-\d{2}$/).required().isoDate(),
    title: joi.string().max(150).regex(/^[^\n]+$/).required(),
    author: joi.object().keys(
        {
            name: joi.string().required(),
            username: joi.string().required().allow(null),
            website: joi.string().required().allow(null)
        }
    ),
    module_name: joi.string().required(),
    publish_date: joi.string().regex(/^\d{4}-\d{2}-\d{2}$/).required().isoDate(),
    vulnerable_versions: joi.alternatives().when("patched_versions", {
        is: null,
        then: joi
            .semver()
            .validRange()
            .required(),
        otherwise: joi
            .semver()
            .validRange()
            .allow(null)
            .required()
    }),
    overview: joi.string().required(),
    recommendation: joi.string().allow(null).required(),
    references: joi.array().allow(null).required(),
});

function validate(dir, model) {
    recursive(dir, (err, pathList) => {
        if (err) throw err;
        pathList.forEach((filePath) => {
            console.log('Validate:', filePath);
            try {
                const vuln = JSON.parse(fs.readFileSync(filePath));
                const result = joi.validate(vuln, model);
                if (result.error) {
                    throw result.error;
                }
            } catch (err) {
                console.log(`File ${filePath}:`);
                console.log(err);
                process.exitCode = 1;
            }
        });
    });
}

validate(vulnPaths.ecosystem, npmModel);
