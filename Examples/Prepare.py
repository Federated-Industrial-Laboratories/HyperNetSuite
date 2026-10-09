#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare five inert sample pages and canonical media for preview or publication.

Inputs: --suite, a new --output directory and optional public --bindings JSON.
Output: page sources, converted media, manifests and an index. No network use.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


Names = ['MarketSquare', 'JuniperAndSteam', 'NightjarBooks', 'FernAndFoundry', 'FieldGuide']
PageIds = {name: hashlib.sha256(('HyperNetExample/' + name).encode()).hexdigest()[:32] for name in Names}


def component(name, **attributes):
    return '@' + name + ' ' + json.dumps(attributes, ensure_ascii=True, separators=(',', ':')) + '\n'


def text(value, colour='Default', **attributes):
    return component('Text', value=value, colour=colour, **attributes)


def panel(label, colour, body, **attributes):
    return component('Panel', label=label, colour=colour, padding=1, **attributes) + body + '@End\n'


def prepare(suite, output, bindings):
    keys = ['network', 'author', 'mediaHost', 'recipient', 'recipientOwner']
    if set(bindings) != set(keys) or any(not isinstance(bindings[k], str) or not re.fullmatch('[a-f0-9]{64}', bindings[k]) for k in keys):
        raise ValueError('Bindings require exactly five lowercase 64-digit public identifiers')
    output.mkdir(mode=0o700)
    media = output / 'Media'
    media.mkdir(mode=0o700)
    source = Path(__file__).resolve().parent
    assets = {}
    for name, extension in [('Square', 'svg'), ('Cafe', 'png'), ('Books', 'svg'), ('Botanical', 'svg')]:
        target = media / (name + ('.Raster' if extension == 'png' else '.Vector'))
        manifest = media / (name + '.Asset')
        result = subprocess.run([str(suite), 'media', 'import', '--input', str(source / (name + '.' + extension)),
            '--output', str(target), '--manifest', str(manifest), '--id', name, '--host', bindings['mediaHost']],
            capture_output=True, timeout=12)
        if result.returncode:
            raise ValueError('Media import failed: ' + name + ': ' + result.stderr.decode(errors='replace'))
        assets[name] = json.loads(manifest.read_text())

    def link(name, label, colour='BrightCyan'):
        uri = 'hypernet://' + bindings['network'] + '/' + bindings['author'] + '/Showcase/' + PageIds[name]
        return component('Button', label=label, colour=colour, action={'kind': 'Navigate', 'target': uri})

    def image(name, label, rows=9, effect=None):
        attributes = {'id': name + 'Picture', 'asset': name, 'alt': label, 'rows': rows, 'fit': 'Contain'}
        if effect:
            attributes['motion'] = {'preset': effect, 'durationMs': 6000}
        return component('Image', **attributes) + component('Button', label='Reveal ' + label,
            colour='BrightYellow', action={'kind': 'Reveal', 'target': name + 'Picture'})

    def column(body):
        return component('Column', gap=1) + body + '@End\n'

    def row(*bodies):
        return component('Row', minChildColumns=28, gap=2) + ''.join(column(b) for b in bodies) + '@End\n'

    def page(title, asset, body):
        return 'HyperNetPage/2\n# ' + title + '\n' + component('Asset', **assets[asset]) + body

    home = page('Willowmere / Market Square', 'Square',
        text('WILLOWMERE  /  GOOD THINGS CLOSE TO HOME', 'BrightCyan', bold=True) +
        text('A fictional neighbourhood of independent shops. Pick a doorway and explore.', 'White') +
        image('Square', 'the market square', 8) +
        row(panel('JUNIPER & STEAM', 'BrightYellow',
                  text('Slow mornings. Excellent coffee.', 'BrightWhite', bold=True) +
                  ': A warm window seat, small-batch bakes and a changing coffee menu.\n' +
                  link('JuniperAndSteam', 'Visit the cafe', 'BrightYellow')),
            panel('NIGHTJAR BOOKS', 'BrightMagenta',
                  text('A shelf for every curiosity.', 'BrightWhite', bold=True) +
                  ': Independent stories, staff favourites and a reading circle after dark.\n' +
                  link('NightjarBooks', 'Browse the bookshop', 'BrightMagenta')),
            panel('FERN & FOUNDRY', 'BrightGreen',
                  text('Make room for something green.', 'BrightWhite', bold=True) +
                  ': Indoor plants, handmade pots and patient advice for new growers.\n' +
                  link('FernAndFoundry', 'Enter the plant studio', 'BrightGreen'))) +
        panel('ON THE NOTICEBOARD', 'Cyan',
              text('SAT / coffee tasting    SUN / book swap    WED / repotting table', 'BrightCyan',
                   id='MarketNews', motion={'preset': 'TextScroll', 'durationMs': 7000}) +
              ': These are sample listings; explore freely without making real bookings.\n') +
        link('FieldGuide', 'Open the field guide') +
        text('Tab selects. Enter opens or reveals. b goes back. a starts or pauses local effects.', 'BrightBlack'))

    form = component('Form', id='CafeEnquiry', label='Ask Juniper & Steam', profile='HyperNetFormMail/1',
        recipient=bindings['recipient'], owner=bindings['recipientOwner'])
    form += component('Field', id='Name', label='Your name', kind='Text', maxBytes=96, required=True)
    form += component('Field', id='Topic', label='I am interested in', kind='Choice',
        options=['Coffee tasting', 'A table for friends', 'Something else'], required=True)
    form += component('Field', id='Guests', label='Number of guests', kind='Integer', minimum=1, maximum=12)
    form += component('Field', id='Message', label='Your message', kind='Multiline', maxBytes=512, required=True)
    form += component('Submit', label='Review private enquiry') + '@End\n'
    cafe = page('Juniper & Steam / Coffee and company', 'Cafe',
        text('JUNIPER & STEAM', 'BrightYellow', bold=True) +
        text('Coffee, conversation, and a little room to breathe.', 'White', id='CafeMotto',
             motion={'preset': 'ColourPulse', 'durationMs': 6000}) +
        image('Cafe', 'our window-side coffee', 12, 'ImagePan') +
        row(panel('FROM THE BAR', 'Yellow',
                  ': House espresso / cocoa, hazelnut, a soft finish\n: Oat flat white / smooth and gently sweet\n: Filter of the day / ask what is brewing\n'),
            panel('FROM THE OVEN', 'BrightYellow',
                  ': Butter croissant / crisp layers, baked this morning\n: Orange and almond slice / bright and fragrant\n: Rosemary focaccia / olive oil and sea salt\n')) +
        panel('TAKE YOUR TIME', 'Cyan',
              ': Find us beside the bookshop, under the green awning.\n: Sample opening hours: Tuesday to Sunday, 08:00 to 17:00.\n' +
              text('Tasting table / 6 of 10 seats prepared', 'BrightCyan') +
              component('Progress', id='CafeSeats', label='Tasting table', value=6, maximum=10,
                        motion={'preset': 'ProgressSweep', 'durationMs': 6000})) +
        ': Send a fictional enquiry to this instance\'s private cafe inbox. You review and confirm before anything is sent.\n' +
        form + link('MarketSquare', 'Return to the square'))

    picks = ''.join('### ' + title + '\n: ' + description + '\n' for title, description in [
        ('The Atlas of Small Adventures', 'Walk a familiar street in a new direction. An imagined collection of journeys close to home.'),
        ('A Window Full of Weather', 'A fictional illustrated notebook of clouds, light and slow observation.'),
        ('The Midnight Orchard', 'An invented gentle mystery about a gardener, a missing map and a very talkative village.'),
        ('Notes from the Listening Room', 'Imaginary essays on music, memory and the songs that make a place feel like home.'),
        ('Little Repairs, Lasting Things', 'A sample practical guide to mending favourite objects and keeping their stories alive.'),
        ('The Long Way to Breakfast', 'A made-up travel diary with too many detours and exactly the right number of bakeries.')])
    books = page('Nightjar Books / Stay for another chapter', 'Books',
        text('NIGHTJAR BOOKS', 'BrightMagenta', bold=True) +
        text('Independent shelves. Unexpected discoveries.', 'White') +
        image('Books', 'the illustrated bookshelf', 8) +
        panel('STAFF FAVOURITES', 'Magenta',
              component('ScrollBox', id='ReadingShelf', label='Six imagined books to explore', rows=9, colour='White') + picks + '@End\n') +
        row(component('Button', label='Focus the shelf', action={'kind': 'Focus', 'target': 'ReadingShelf'}, colour='BrightMagenta'),
            component('Button', label='See the final recommendation', action={'kind': 'Scroll', 'target': 'ReadingShelf', 'direction': 'End'}, colour='Cyan')) +
        panel('AFTER HOURS', 'BrightBlue',
              ': The reading circle meets around the long table. Bring a favourite passage, or just listen.\n' +
              text('Next sample gathering / Thursday / 18:30', 'BrightWhite', id='BookNews',
                   motion={'preset': 'TextFade', 'durationMs': 5000})) +
        link('JuniperAndSteam', 'Take your next chapter to the cafe', 'BrightYellow') +
        link('MarketSquare', 'Return to the square'))

    plants = page('Fern & Foundry / A little more green', 'Botanical',
        text('FERN & FOUNDRY', 'BrightGreen', bold=True) +
        text('Plants, pots, and the pleasure of helping things grow.', 'White') +
        image('Botanical', 'our botanical illustration', 9, 'ImageFade') +
        row(panel('EASY COMPANY', 'Green', ': Pothos / trailing leaves for a bright corner\n: Snake plant / a sculptural, patient companion\n: Peperomia / small leaves, plenty of character\n'),
            panel('MADE BY HAND', 'Yellow', ': Terracotta bowls / warm and tactile\n: Speckled planters / simple shapes, soft colours\n: Cork mats / a quiet place to put down roots\n')) +
        panel('THE PROPAGATION BENCH', 'BrightGreen',
              ': This static sample records 24 cuttings taking root. The sweep is a local decoration.\n' +
              component('Progress', id='Cuttings', label='Rooted cuttings', value=24, maximum=32,
                        motion={'preset': 'ProgressSweep', 'durationMs': 7000}),
              id='Greenhouse', motion={'preset': 'BorderEmphasis', 'durationMs': 7000}) +
        component('Button', label='Animate the greenhouse border', colour='BrightGreen',
                  action={'kind': 'Motion', 'target': 'Greenhouse', 'running': True}) +
        ': At the sample repotting table: bring a pot, choose a plant, and leave with a story.\n' +
        link('MarketSquare', 'Return to the square'))

    guide_text = ''.join('### ' + heading + '\n: ' + body + '\n' for heading, body in [
        ('Find your way', 'Use Tab and Shift-Tab to select controls. Enter opens a selected page or activates a button. Use b to return through your history.'),
        ('Look a little closer', 'Images begin as meaningful descriptions. Activate Reveal to request and verify the static asset. An unsupported terminal retains the description.'),
        ('Move at your own pace', 'Arrow keys scroll the page. Focus a scrollbox to move within it. PageUp and PageDown cover longer distances. Resizing reflows the content.'),
        ('A little motion', 'Press a to enable or pause finite local effects. Each activation ends within ten seconds. Images never arrive as a stream of animation frames.'),
        ('Send a private enquiry', 'The cafe form uses a separate mail identity. Complete the fields, select Review, inspect the recipient and exact values, then confirm or cancel.'),
        ('Read the reply data', 'The cafe receiver accepts only the exact published form. Its inbox exposes typed enquiry data. No order, payment or booking is performed.'),
        ('Make your own page', 'Start with a title and paragraphs, then add declarative panels, rows, colours and buttons. Source contains data only and is reviewed before publication.'),
        ('Use original artwork', 'Import PNG, JPEG or a supported static SVG. The importer produces bounded canonical content; unsupported visual features are refused.'),
        ('Know what is shared', 'The signed source names each asset digest, dimensions, storage hosts and required copies. New stores need their own consent.'),
        ('Keep a useful fallback', 'Read with graphics off or use plain output. Colour and motion add presentation; the labels and page content remain meaningful without them.'),
        ('Leave and return', 'q exits the reader. The private instance keeps its data and continues running until its Stop command is used.'),
        ('About this neighbourhood', 'Willowmere and all businesses, books, events and opening hours are fictional examples for exploring HyperNet.')])
    guide = page('Willowmere / Field guide', 'Square',
        text('A FIELD GUIDE TO THE SQUARE', 'BrightCyan', bold=True) +
        image('Square', 'the neighbourhood illustration', 6) +
        component('ScrollBox', id='Guide', label='Twelve notes for exploring', rows=14, colour='Cyan') + guide_text + '@End\n' +
        component('Button', label='Focus the guide', action={'kind': 'Focus', 'target': 'Guide'}, colour='BrightCyan') +
        component('Button', label='Jump to the final note', action={'kind': 'Scroll', 'target': 'Guide', 'direction': 'End'}, colour='Yellow') +
        link('MarketSquare', 'Return to the square'))

    pages = dict(zip(Names, [home, cafe, books, plants, guide]))
    for name, body in pages.items():
        target = output / (name + '.Page')
        target.write_text(body)
        target.chmod(0o600)
        result = subprocess.run([str(suite), 'pages', 'preview', str(target), '--ascii'], capture_output=True, timeout=8)
        if result.returncode:
            raise ValueError('Page validation failed: ' + name + ': ' + result.stderr.decode(errors='replace'))
    index = {'namespace': 'Showcase', 'pageIds': PageIds, 'bindings': bindings,
             'pages': {name: name + '.Page' for name in pages},
             'assets': {name: {'manifest': 'Media/' + name + '.Asset',
                'bytes': 'Media/' + name + ('.Raster' if name == 'Cafe' else '.Vector')} for name in assets}}
    (output / 'Index.json').write_text(json.dumps(index, indent=2) + '\n')
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--bindings', type=Path, help='Five public identifiers; defaults permit local preview only')
    args = parser.parse_args()
    os.umask(0o077)
    keys = ['network', 'author', 'mediaHost', 'recipient', 'recipientOwner']
    bindings = json.loads(args.bindings.read_text()) if args.bindings else {key: str(i) * 64 for i, key in enumerate(keys)}
    index = prepare(args.suite.resolve(), args.output.resolve(), bindings)
    print(json.dumps({'output': str(args.output.resolve()), 'pages': index['pageIds'], 'networkUsed': False}))


if __name__ == '__main__':
    main()
