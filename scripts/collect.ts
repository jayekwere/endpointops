import { collect } from '../src/collector.js';
import { Id } from '../src/security.js';
const id = Id.parse(process.argv[2] ?? 'local-observation');
console.log(JSON.stringify(collect(id), null, 2));
