import { useMemo, useRef, useState, type ReactNode } from 'react'
import { useFrame } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import * as THREE from 'three'
import type { Technology } from '../data/types'
import { getLevel } from '../lib/risk'

interface Props {
  tech: Technology
  position: [number, number, number]
  selected: boolean
  dimmed: boolean
  onSelect: () => void
}

/** Data-source independent description of one pyramid: Technology Risk Mode and News Attention Mode both render through PyramidBase. */
export interface PyramidSpec {
  id: string
  label: string
  sublabel?: string
  color: string
  heightFactor: number      // 0.85 .. 1.15
  tooltip: ReactNode
}
interface BaseProps { spec: PyramidSpec; position: [number, number, number]; selected: boolean; dimmed: boolean; onSelect: () => void }

const H = 2.6
const R = 1.35

/** Technology Risk Mode: colour and height come from the Threat Signal Score exactly as before. */
export default function Pyramid({ tech, position, selected, dimmed, onSelect }: Props) {
  const level = getLevel(tech.score)
  const spec: PyramidSpec = {
    id: tech.id, label: tech.name, color: level.color, heightFactor: 0.85 + ((tech.score ?? 0) / 100) * 0.3,
    tooltip: (
      <>
        <div className="text-xs font-semibold text-ink">{tech.name}</div>
        <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-mute">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: level.color }} />
          Risk Score <span className="font-semibold text-ink">{tech.score === null ? 'N/A' : Math.round(tech.score)}</span>
        </div>
      </>
    ),
  }
  return <PyramidBase spec={spec} position={position} selected={selected} dimmed={dimmed} onSelect={onSelect} />
}

export function PyramidBase({ spec, position, selected, dimmed, onSelect }: BaseProps) {
  const group = useRef<THREE.Group>(null)
  const mat = useRef<THREE.MeshStandardMaterial>(null)
  const wire = useRef<THREE.LineBasicMaterial>(null)
  const ring = useRef<THREE.MeshBasicMaterial>(null)
  const [hovered, setHovered] = useState(false)
  const target = useMemo(() => new THREE.Color(spec.color), [spec.color])
  const edges = useMemo(() => new THREE.EdgesGeometry(new THREE.ConeGeometry(R, H, 4)), [])
  const active = hovered || selected

  // Height scales slightly with the pyramid's own measure for quick visual reading.
  const targetY = (active ? 1.08 : 1) * spec.heightFactor
  const targetXZ = active ? 1.05 : 1

  useFrame((_, dt) => {
    const k = 1 - Math.exp(-dt * 6)
    if (mat.current) {
      mat.current.color.lerp(target, k)
      mat.current.emissive.lerp(target, k)
      mat.current.emissiveIntensity = THREE.MathUtils.lerp(mat.current.emissiveIntensity, active ? 0.65 : 0.22, k)
      mat.current.opacity = THREE.MathUtils.lerp(mat.current.opacity, dimmed ? 0.35 : 0.94, k)
    }
    if (wire.current) wire.current.color.lerp(target, k)
    if (ring.current) {
      ring.current.color.lerp(target, k)
      ring.current.opacity = THREE.MathUtils.lerp(ring.current.opacity, active ? 0.9 : 0.25, k)
    }
    if (group.current) {
      const g = group.current
      g.scale.set(
        THREE.MathUtils.lerp(g.scale.x, targetXZ, k),
        THREE.MathUtils.lerp(g.scale.y, targetY, k),
        THREE.MathUtils.lerp(g.scale.z, targetXZ, k),
      )
      g.rotation.y += dt * (selected ? 0.5 : 0.08)
    }
  })

  return (
    <group position={position}>
      <group
        ref={group}
        onPointerOver={(e) => {
          e.stopPropagation()
          setHovered(true)
          document.body.style.cursor = 'pointer'
        }}
        onPointerOut={() => {
          setHovered(false)
          document.body.style.cursor = 'auto'
        }}
        onClick={(e) => {
          e.stopPropagation()
          onSelect()
        }}
      >
        <mesh position={[0, H / 2, 0]} rotation={[0, Math.PI / 4, 0]}>
          <coneGeometry args={[R, H, 4]} />
          <meshStandardMaterial
            ref={mat}
            color={spec.color}
            emissive={spec.color}
            emissiveIntensity={0.22}
            metalness={0.35}
            roughness={0.35}
            transparent
            flatShading
          />
        </mesh>
        <lineSegments position={[0, H / 2, 0]} rotation={[0, Math.PI / 4, 0]} geometry={edges}>
          <lineBasicMaterial ref={wire} color={spec.color} transparent opacity={0.9} />
        </lineSegments>
      </group>

      {/* base ring */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.01, 0]}>
        <ringGeometry args={[R * 1.5, R * 1.56, 64]} />
        <meshBasicMaterial ref={ring} color={spec.color} transparent opacity={0.25} side={THREE.DoubleSide} />
      </mesh>

      {/* name label */}
      <Html position={[0, 0, R * 1.9]} center style={{ pointerEvents: 'none' }} zIndexRange={[10, 0]}>
        <div className={`whitespace-nowrap text-[12px] font-medium tracking-wide transition-colors ${active ? 'text-ink' : 'text-mute'}`}>
          {spec.label}
          {spec.sublabel && <div className="text-center text-[10px] font-normal tabular-nums text-mute">{spec.sublabel}</div>}
        </div>
      </Html>

      {hovered && (
        <Html position={[0, H * 1.25, 0]} center style={{ pointerEvents: 'none' }} zIndexRange={[20, 10]}>
          <div className="whitespace-nowrap rounded-lg border border-line bg-surface/95 px-3 py-2 shadow-xl backdrop-blur">
            {spec.tooltip}
          </div>
        </Html>
      )}
    </group>
  )
}
