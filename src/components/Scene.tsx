import { Canvas } from '@react-three/fiber'
import { OrbitControls, Grid } from '@react-three/drei'
import type { Technology } from '../data/types'
import type { ReactNode } from 'react'
import Pyramid from './Pyramid'

interface Props {
  technologies: Technology[]
  selectedId: string | null
  onSelect: (id: string | null) => void
}

const COLS = 3
const GAP = 5

const slot = (i: number, n: number, cols = COLS): [number, number, number] => {
  const rows = Math.ceil(n / cols)
  const col = i % cols
  const row = Math.floor(i / cols)
  return [(col - (cols - 1) / 2) * GAP, 0, (row - (rows - 1) / 2) * GAP]
}

/** Technology Risk Mode (unchanged behaviour). */
export default function Scene({ technologies, selectedId, onSelect }: Props) {
  return (
    <SceneBase items={technologies} selectedId={selectedId} onSelect={onSelect}
      renderItem={(t, position, selected, dimmed) => <Pyramid key={t.id} tech={t} position={position} selected={selected} dimmed={dimmed} onSelect={() => onSelect(t.id)} />} />
  )
}

/** Shared canvas (camera, lights, grid, orbit controls, layout) for any pyramid data source. */
export function SceneBase<T extends { id: string }>({ items, selectedId, onSelect, renderItem, cols = COLS }: {
  items: T[]; selectedId: string | null; onSelect: (id: string | null) => void; cols?: number
  renderItem: (item: T, position: [number, number, number], selected: boolean, dimmed: boolean) => ReactNode
}) {
  const technologies = items
  const extra = Math.max(0, Math.ceil(technologies.length / cols) - 2) * 3.2   // pull the camera back when many pyramids are shown (max 24)
  return (
    <Canvas
      key={Math.round(extra)}
      dpr={[1, 1.75]}
      camera={{ position: [0, 9 + extra, 14 + extra], fov: 42 }}
      onPointerMissed={() => onSelect(null)}
    >
      <color attach="background" args={['#090D16']} />
      <fog attach="fog" args={['#090D16', 18, 40]} />
      <ambientLight intensity={0.55} />
      <directionalLight position={[6, 12, 8]} intensity={1.2} />
      <pointLight position={[-8, 5, -6]} intensity={30} color="#22D3EE" />

      <Grid
        position={[0, -0.01, 0]}
        args={[60, 60]}
        cellSize={1}
        cellThickness={0.5}
        cellColor="#16233a"
        sectionSize={5}
        sectionThickness={1}
        sectionColor="#1f3a52"
        fadeDistance={32}
        fadeStrength={1.5}
        infiniteGrid
      />

      {technologies.map((t, i) => renderItem(t, slot(i, technologies.length, cols), selectedId === t.id, !!selectedId && selectedId !== t.id))}

      <OrbitControls
        enablePan={false}
        enableDamping
        dampingFactor={0.08}
        minDistance={7}
        maxDistance={26}
        maxPolarAngle={Math.PI / 2.2}
        target={[0, 1, 0]}
      />
    </Canvas>
  )
}
