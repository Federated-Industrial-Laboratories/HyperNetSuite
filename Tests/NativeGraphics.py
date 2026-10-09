#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the installed Suite in real native terminals on an isolated X display."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from PIL import Image


def run(*args, **kwargs):
    kwargs.setdefault('timeout', 15)
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True, **kwargs)


def wait_window(title, process):
    deadline = time.monotonic()+15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('terminal exited before its window appeared')
        value = subprocess.run(['xdotool', 'search', '--onlyvisible', '--name', '^'+title+'$'], capture_output=True, text=True)
        if value.returncode == 0 and value.stdout.strip():
            return value.stdout.strip().splitlines()[-1]
        time.sleep(.1)
    raise RuntimeError('terminal window deadline exceeded')


def capture(directory, name, window):
    path = directory/(name+'.png')
    run('import', '-window', window, path)
    image = Image.open(path).convert('RGB')
    # Fixture pixels use cyan/blue and orange; default terminal text is grayscale.
    # Uniform coloured blocks distinguish image fills from subpixel font fringes.
    pixels=image.load();coloured=0
    for y in range(0,image.height-3,4):
        for x in range(0,image.width-3,4):
            colour=pixels[x,y]
            if max(colour)-min(colour)>60 and max(colour)>100 and all(
                max(abs(a-b) for a,b in zip(pixels[x+dx,y+dy],colour))<5
                for dy in range(4) for dx in range(4)):
                coloured+=16
    return {'file':str(path),'width':image.width,'height':image.height,'colouredPixels':coloured,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser=argparse.ArgumentParser()
    for key in ['suite','kitty','wezterm','xterm','output']:
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--adapter', action='append', choices=['kitty', 'sixel', 'i-term2'])
    args=parser.parse_args()
    suite=Path(args.suite).resolve(); output=Path(args.output).resolve();output.mkdir(mode=0o700)
    root=Path(tempfile.mkdtemp(prefix='HyperNetNativeGraphics'))
    for name in ['TerminalCache','TerminalConfig']:
        (root/name).mkdir(mode=0o700)
    records=[]; errors=[]
    try:
        svg=root/'Input.svg'
        svg.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="240" height="160"><rect width="240" height="160" fill="#0088cc"/><path d="M20 20L220 140L20 140Z" fill="#ffaa00"/></svg>')
        asset=root/'Vector.bin'; manifest=root/'Manifest.json'
        converted=json.loads(run(suite,'media','import','--input',svg,'--output',asset,'--manifest',manifest,'--id','Diagram','--host','01'*32).stdout)
        specification=converted['asset']
        source=root/'Page.txt'
        source.write_text('HyperNetPage/2\n# Native graphics qualification\n: Static local geometry, explicit reveal, no network.\n'
            +'@Asset '+json.dumps(specification,separators=(',',':'))+'\n'
            +'@Button {"label":"Reveal diagram","action":{"kind":"Reveal","target":"Picture"}}\n'
            +'@Row {"minChildColumns":24,"gap":2}\n@Column {}\n@Panel {"label":"Clipping boundary","padding":1}\n'
            +'@ScrollBox {"id":"Viewport","label":"Image viewport","rows":5}\n'
            +'@Image {"id":"Picture","asset":"Diagram","alt":"Cyan and orange geometry","rows":10,"fit":"Cover","motion":{"preset":"ImagePan","durationMs":2000}}\n'
            +'@End\n@End\n@End\n@Column {}\n: This adjacent text must remain visible.\n@End\n@End\n'
            +'@Text {"id":"Banner","value":"Motion is generated locally","motion":{"preset":"ColourPulse","durationMs":2000}}\n'
            +': Page footer stays outside the image viewport.\n')
        wrapper=root/'TerminalSession.py'
        wrapper.write_text('''import fcntl,json,os,re,select,struct,subprocess,sys,termios,time,tty
from pathlib import Path
record=Path(sys.argv[1]);command=sys.argv[2:]
original=termios.tcgetattr(0);tty.setraw(0)
os.write(1,b'\\x1b[16t');response=b'';deadline=time.monotonic()+2
while time.monotonic()<deadline:
    if select.select([0],[],[],.1)[0]:
        response+=os.read(0,128)
        if b't' in response:break
termios.tcsetattr(0,termios.TCSANOW,original)
match=re.search(rb'\\x1b\\[6;(\\d+);(\\d+)t',response)
if match:
    height,width=map(int,match.groups())
else:
    rows,cols,xpixels,ypixels=struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8))
    if not rows or not cols or not xpixels or not ypixels or xpixels%cols or ypixels%rows:
        record.write_text(json.dumps({'error':'no exact cell geometry','response':response.hex(),'winsize':[rows,cols,xpixels,ypixels]}))
        raise SystemExit('terminal did not report exact cell geometry')
    width,height=xpixels//cols,ypixels//rows
record.write_text(json.dumps({'cellWidth':width,'cellHeight':height}))
result=subprocess.run(command+['--graphics-cell-width',str(width),'--graphics-cell-height',str(height)])
print('TERMINAL RESTORED - IMAGE CLEARED',flush=True)
record.write_text(json.dumps({'cellWidth':width,'cellHeight':height,'exitCode':result.returncode,'terminalRestored':termios.tcgetattr(0)==original}))
time.sleep(5)
''')
        for adapter,binary in [('kitty',args.kitty),('sixel',args.xterm),('i-term2',args.wezterm)]:
            if args.adapter and adapter not in args.adapter:
                continue
            title='HyperNetNative'+adapter.replace('-','')
            geometry=output/(title+'Session.json')
            command=['python3',str(wrapper),str(geometry),str(suite),'pages','preview',str(source),'--tui','--graphics',adapter,'--media','Diagram='+str(asset)]
            if adapter=='kitty':
                prefix=[binary,'--config','NONE','--title',title,'-o','linux_display_server=x11','-o','font_family=DejaVu Sans Mono','-o','font_size=12','-o','remember_window_size=no','-o','initial_window_width=90c','-o','initial_window_height=28c','-o','shell_integration=disabled','-o','enable_audio_bell=no']
            elif adapter=='sixel':
                prefix=[binary,'-fa','DejaVu Sans Mono','-fs','12','-b','0','-geometry','90x28','-tn','xterm-256color','-ti','vt340','-xrm','XTerm*sixelScrolling: true','-title',title,'-e']
            else:
                prefix=[binary,'--skip-config','--config','enable_wayland=false','--config','font_size=12','--config','initial_cols=90','--config','initial_rows=28','--config','enable_tab_bar=false','--config','front_end="Software"','start','--always-new-process','--class',title,'--']
            environment=dict(os.environ,LIBGL_ALWAYS_SOFTWARE='1',
                XDG_CACHE_HOME=str(root/'TerminalCache'),XDG_CONFIG_HOME=str(root/'TerminalConfig'))
            for key in ['WAYLAND_DISPLAY','SSH_CONNECTION','SSH_TTY','TMUX','STY']:
                environment.pop(key,None)
            log=output/(title+'.log')
            with log.open('w') as trace:
                process=subprocess.Popen(prefix+command,env=environment,stdout=trace,stderr=trace)
                try:
                    if adapter=='i-term2':
                        # WezTerm's default title follows the child; match its explicit class.
                        deadline=time.monotonic()+15;window=None
                        while time.monotonic()<deadline:
                            found=subprocess.run(['xdotool','search','--onlyvisible','--class',title],capture_output=True,text=True)
                            if found.returncode==0 and found.stdout.strip():window=found.stdout.strip().splitlines()[-1];break
                            if process.poll() is not None:break
                            time.sleep(.1)
                        if not window:raise RuntimeError('WezTerm window unavailable')
                    else:window=wait_window(title,process)
                    run('xdotool','windowfocus','--sync',window)
                    deadline=time.monotonic()+6
                    while not geometry.exists() and time.monotonic()<deadline:time.sleep(.1)
                    assert geometry.exists(),'no measured geometry'
                    detail=json.loads(geometry.read_text())
                    assert 'error' not in detail,detail
                    time.sleep(.5)
                    before=capture(output,title+'Before',window)
                    assert before['colouredPixels']<1000,'image pixels appeared before explicit reveal'
                    run('xdotool','key','Tab','Return');time.sleep(1.5)
                    revealed=capture(output,title+'Revealed',window)
                    assert revealed['colouredPixels']>before['colouredPixels']+1000,'no native image rendering detected'
                    run('xdotool','key','a');time.sleep(.7)
                    moving=capture(output,title+'Motion',window)
                    run('xdotool','key','a','Tab','Down','Down');time.sleep(.7)
                    scrolled=capture(output,title+'Scrolled',window)
                    assert scrolled['colouredPixels']>before['colouredPixels']+1000,'image did not recover after rapid local scrolling'
                    width=int(revealed['width']*.76);height=int(revealed['height']*.82)
                    run('xdotool','windowsize',window,width,height);time.sleep(.7)
                    resized=capture(output,title+'Resized',window)
                    assert resized['colouredPixels']>1000,'image did not recover after resize'
                    run('xdotool','key','q');time.sleep(.5)
                    restored=capture(output,title+'Restored',window)
                    detail=json.loads(geometry.read_text())
                    assert detail['exitCode']==0 and detail['terminalRestored'],'terminal mode not restored'
                    assert restored['colouredPixels']<1000,'graphics remain after alternate-screen cleanup'
                    records.append({'adapter':adapter,'binary':str(binary),
                        'terminalSha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                        'geometry':detail,'frames':[before,revealed,moving,scrolled,resized,restored]})
                except Exception as error:
                    errors.append({'adapter':adapter,'error':str(error),'log':str(log)})
                finally:
                    process.terminate()
                    try:process.wait(timeout=3)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
    finally:
        shutil.rmtree(root)
        (output/'Result.json').write_text(json.dumps({'suiteSha256':hashlib.sha256(suite.read_bytes()).hexdigest(),'testSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'results':records,'errors':errors},indent=2)+'\n')
    if errors:raise SystemExit(1)


if __name__=='__main__':main()
